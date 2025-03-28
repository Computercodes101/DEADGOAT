import os
import re
import random
import time

import httpx
import ollama
import requests

def os_ify_path(path: str) -> str:
    """
    Swaps "/" for "\" and vise versa as os appropriate
    :param path:
    :return:
    """

    if os.name == "nt":
        return path.replace("/", "\\")
    return path.replace("\\", "/")

#Unfamiliar with the "flows" section, sorry
cur_file = os_ify_path(os.path.dirname(os.path.realpath(__file__)))
src_dir = os_ify_path(os.path.split(cur_file)[0])
root_dir = os_ify_path(os.path.split(src_dir)[0])
# print(src_dir)
# hotspots = json.loads(
#     open(os.path.join(
#         src_dir,
#         "example_hotspots.json"
#     )).read()
# )["hotspots"]

base_uri = "https://sonarcloud.io/"
headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Authorization": f"Bearer {os.environ['SONARQUBE_API']}"
}

hotspots = requests.get(
    base_uri + "api/hotspots/search",
    headers=headers,
    params={
        "projectKey": os.environ["SONARQUBE_PROJECT_KEY"],
        "ps": 100,
        "status": "TO_REVIEW",
        "deprecated": False,
        "section":"params",
    }
).json()["hotspots"]

def parse_spot(spot: dict) -> tuple[str, str, str]:
    """
    Given a hotspot as a dictionary, parse it and return the relevant code

    If the

    :param spot: The hotspot from the list
    :return: (<parent object>, <lines>, <file>)
    """

    file_path = spot["component"].split(":")[1]
    file_path = os_ify_path(os.path.join(root_dir, file_path))
    msg = spot["message"]
    blame = spot["author"]
    rule_key = spot["ruleKey"]
    with open(file_path) as f:
        text = f.read()
    print(f"{msg} of type {rule_key} in {file_path} written by {blame}")


    lines = text.split("\n")
    start_line, end_line = curly_context(lines, spot["line"])

    fun_text = "\n".join(lines[start_line:end_line + 1])

    vuln_line = ""
    i = spot["line"] - 1
    while not vuln_line.endswith(";") and i < len(lines):
        vuln_line += " " + lines[i].strip()
        i += 1

    imports = "\n".join(filter(lambda x: "import" in x, lines))

    return fun_text, vuln_line, imports

def curly_context(text: list[str], start: int) -> tuple[int, int]:
    """
    Pulls the parent object/function/class

    :param text: list of text lines
    :param start: start line
    :return: (start, end)
    """
    #TODO: 
    function_regex = re.compile(
        r"\w*\s+"  # return type
        r"\w+\s*"  # function name
        r"(?!(if\s*\()|(catch\s*\())" # negative lookaround - prevents matching (catch) or (if)
        r"\([^)]*\)\s*"  # function parameters
        r"((throws)\s\w+\s)*"  # throw type
        r"\{",  # start of function
        re.MULTILINE & re.IGNORECASE,
    )

    class_regex = re.compile(
        r"class\s+"  # start with `class`
        r"\w+\s+"  # class name
        r"(((extends)|(implements))\s+\w+\s+)*"  # option inheritance
        r"\{",
        re.IGNORECASE & re.MULTILINE,
    )

    start_line = 0

    # start at line "spot['line']" and work backwards until a line matches
    for i in range(start, -1, -1):
        line = text[i]
        if len(function_regex.findall(line)) + len(class_regex.findall(line)) > 0:
            start_line = i
            break

    # work our way down the function until we have closed all parenthesis
    rem_paren = 0
    end_line = start_line
    for i in range(start_line, len(text)):
        line = text[i]
        rem_paren += line.count("{")
        rem_paren -= line.count("}")
        if rem_paren == 0:
            end_line = i
            break

    end_line = min(end_line, len(text) - 1)
    if end_line == 0:
        end_line = len(text) - 1

    return start_line, end_line


exam = """
Here is an example user message:

The following java snippet contains the vulnerability `'password' detected in this expression, review this potentially hard-coded secret.` with a HIGH probability. 
Fix the issue and format your code response as a markdown code block with the following format contained within `'''`:

'''
**Fixed Parent Section**
```java
...
```

**Imports**
```java
...
```

**Explanation**
...
'''
The fixed parent section should not contain the described security vulnerability and should not change any function or class names that already exist in the vulnerable code.

Here is the vulnerable code:
Vulnerable line:
```java
String password = "Hunter1!";
```

Parent section of the vulnerable line:
```java
    public static void main(String[] args) throws IOException {
        String password = "Hunter1!";
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        
        System.out.print("Please enter password: ");
        String user_guess = br.readLine();
        
        if (password.equals(user_guess))
            System.out.println("\nCorrect!");
        else
            System.out.println("\nIncorrect!");
    }
```

Current imports:
```java
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
```

---

Here is he example system response:

**Fixed Parent Section**
```java
public static void main(String[] args) throws IOException {
    String password = System.getenv("PASSWORD");
    BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
    
    System.out.print("Please enter password: ");
    String user_guess = br.readLine();
    
    if (password.equals(user_guess))
        System.out.println("\nCorrect!");
    else
        System.out.println("\nIncorrect!");
}
```

**Imports**
```java
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
```

**Explanation**

To fix the issue, you should be using an environment variable to set the password.
This prevents a hard coded password from being extracted and allows for changing the password each run.
"""
"""
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

class Thing {
    public static void main(String[] args) throws IOException {
        String password = "Hunter1!";
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        
        System.out.print("Please enter password: ");
        String user_guess = br.readLine();
        
        if (password.equals(user_guess))
            System.out.println("\nCorrect!");
        else
            System.out.println("\nIncorrect!");
    }
}
"""

client = ollama.Client(
    host="https://pilot1782.org/desktop",
    auth=httpx.BasicAuth(os.environ["OLLAMA_USER"], os.environ["OLLAMA_PASSWORD"]),
)


def get_fix(oclient: ollama.Client, hotspot: dict) -> tuple[str, str, str]:
    """
    Uses the provided client to generate the fixed parent section.
    :param oclient: Ollama client
    :param hotspot: Spot dictionary
    :return: [<patched parent section>, <new imports>, <explanation>]
    """

    text, line, imp = parse_spot(hotspot)

    prompt = (
        f"The following java snippet contains the vulnerability "
        f"`{hotspot['message']}` with a {hotspot['vulnerabilityProbability']} probability. "
        f"Fix the issue and format your code response as a markdown code block"
        f"with the following format contained within `'''`:"
        f"\n'''\n**Fixed Parent Section**\n"
        f"```java\n"
        f"...\n"
        f"```\n"
        f"\n**Imports**\n"
        f"```java\n"
        f"...\n"
        f"```\n"
        f"\n**Explanation**\n"
        f"...\n'''\n"
        f"The fixed parent section should not contain the described security "
        f"vulnerability and should not change any function or class names that "
        f"already exist in the vulnerable code.\n"
        f"\nHere is the vulnerable code:\n"
        f"Vulnerable line:\n```java\n{line}\n```"
        f"\n\nParent section of the vulnerable line:\n```java\n{text}\n```"
        f"\n\nCurrent imports:\n```java\n{imp}\n```"
    )

    for _ in range(3):
        response = oclient.chat(
            model="qwen2.5-coder:14b",
            messages=[
                {
                    "role": "user",
                    "content": exam
                },
                {
                    "role": "user",
                    "content": prompt,
                }
            ]
        )

        if (
                all([
                    i in response.message.content
                    for i in [
                        "I'm sorry, but I can't help with that.",
                        "**Fixed Parent Section**",
                        "**Explanation**",
                        "**Imports**",
                    ]
                ])
        ):
            break

    if "I'm sorry, but I can't help with that" in response.message.content:
        return text, imp, "No changes were made."

    response_text = response.message.content

    # parse the fixed parent section

    in_section = False
    fixed_parent_text = ""
    for line in response_text.splitlines():
        if "**Fixed Parent Section**" in line:
            in_section = True
        if "```" in line and "java" not in line:
            in_section = False

        if in_section:
            fixed_parent_text += line + "\n"

    fixed_import_text = ""
    for line in response_text.splitlines():
        if "**Imports**" in line:
            in_section = True
        if "```" in line and "java" not in line:
            in_section = False

        if in_section:
            fixed_import_text += line + "\n"

    explanation_text = ""
    for line in response_text.splitlines():
        if "**Explanation**" in line:
            in_section = True

        if in_section:
            explanation_text += line + "\n"

    if not fixed_parent_text or not fixed_import_text or not explanation_text:
        print(f"Text was empty: "
              f"P:{bool(fixed_parent_text)} "
              f"I:{bool(fixed_import_text)} "
              f"E:{bool(explanation_text)}"
              f"\n{response_text}")
        return text, imp, "No changes were made."

    return str(fixed_parent_text), str(fixed_import_text), str(explanation_text)


times = []
for _ in range(1):
    spot = random.choice(hotspots)

    tStart = time.time()
    _, _, explanation = get_fix(client, spot)
    tDuration = time.time() - tStart
    print(f"Patch ({tDuration}s):\n{explanation}")
    times.append(tDuration)

print(f"\n\n----\nAverage response time: {sum(times) / len(times)}s, Min: {min(times)}, Max: {max(times)}")
