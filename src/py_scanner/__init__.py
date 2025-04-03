import datetime
import json
import os
import random
import re
import time
import sys
import subprocess

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


# Unfamiliar with the "flows" section, sorry
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
    "Authorization": f"Bearer {os.environ['SONARQUBE_API']}",
}

print("Fetching data from SonarQube...")
hotspots = requests.get(
    base_uri + "api/hotspots/search",
    headers=headers,
    params={
        "projectKey": os.environ["SONARQUBE_PROJECT_KEY"],
        "ps": 100,
        "status": "TO_REVIEW",
        "deprecated": False,
        "section": "params",
    },
).json()["hotspots"]
print(f"Found {len(hotspots)} hotspots")

print("Fetching repos...")
# subprocess.Popen(
#     f"echo {os.environ['AZURE_DEVOPS_EXT_PAT']} | az devops login",
#     shell=True,
#     stdout=sys.stdout,
#     stderr=sys.stderr,
# )
repos = subprocess.Popen(
    "az repos list",
    shell=True,
    stdout=subprocess.PIPE,
    stderr=sys.stderr,
)
repos = json.loads(repos.stdout.read().decode())
repo = None
for r in repos:
    if r["project"]["name"].strip() == os.environ["AZURE_PROJECT"].strip():
        repo = r
        break
if repo is None:
    print(f"Could not find {os.environ['AZURE_PROJECT']} in\n{repos}")
    sys.exit(1)
print(f"Found {os.environ['AZURE_PROJECT']}")

if len(hotspots) == 0:
    print("No hotspots found, exiting")
    exit(0)

# create a new branch
branch = f"DEADGOAT-{datetime.datetime.now().strftime('%Y%m%d')}-{os.urandom(4).hex()}"
p = subprocess.Popen(
    f"git branch {branch}",
    shell=True,
    stdout=sys.stdout,
    stderr=sys.stderr,
)
p.communicate()
p = subprocess.Popen(
    f"git checkout {branch}",
    shell=True,
    stdout=sys.stdout,
    stderr=sys.stderr,
)
p.communicate()
print(f"Created new branch {branch}")


def parse_spot(hotspot: dict) -> tuple[str, str, str]:
    """
    Given a hotspot as a dictionary, parse it and return the relevant code

    If the

    :param hotspot: The hotspot from the list
    :return: (<parent object>, <lines>, <file>)
    """

    try:
        file_path = hotspot["component"].split(":")[1]
        file_path = os_ify_path(os.path.join(root_dir, file_path))
        msg = hotspot["message"]
        blame = hotspot["author"]
        rule_key = hotspot["ruleKey"]
        with open(file_path) as f:
            text = f.read()
        print(f"{msg} of type {rule_key} in {file_path} written by {blame}")

        lines = text.split("\n")
        start_line, end_line = curly_context(lines, hotspot["line"])

        fun_text = "\n".join(lines[start_line : end_line + 1])

        vuln_line = ""
        i = hotspot["line"] - 1
        while not vuln_line.endswith(";") and i < len(lines):
            vuln_line += " " + lines[i].strip()
            i += 1

        imports = "\n".join(filter(lambda x: "import" in x, lines))

        return fun_text, vuln_line, imports
    except:
        print(f"Error parsing hotspot: {sys.exc_info()[0]}")
        return "", "", ""


def curly_context(text: list[str], start: int) -> tuple[int, int]:
    """
    Pulls the parent object/function/class

    :param text: list of text lines
    :param start: start line
    :return: (start, end)
    """

    function_regex = re.compile(
        r"\w*\s+"  # return type
        r"\w+\s*"  # function name
        r"(?!(if\s*\()|(catch\s*\())" # negative lookaround - prevents matching (catch) or (if)
        r"\([^)]*\)\s*"  # function parameters
        r"((throws)\s\w+\s)*"  # throw type
        r"\{",  # start of function
        re.MULTILINE & re.IGNORECASE,
    )

    decorator_regex = re.compile(r"\s*@(\w+\s*)(\([^)]*\))")

    class_regex = re.compile(
        r"class\s+"  # start with `class`
        r"\w+\s+"  # class name
        r"(((extends)|(implements))\s+(\w+(<\w*>)?)\s+)*"  # option inheritance
        r"\{",
        re.IGNORECASE & re.MULTILINE,
    )

    start_line = 0

    # start at line "spot['line']" and work backwards until a line matches
    for i in range(start, -1, -1):
        line = text[i]
        if (
            len(function_regex.findall(line))
            + len(class_regex.findall(line))
            + len(decorator_regex.findall(line))
            > 0
        ):
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


client = ollama.Client(
    # host="http://desktop-1782.otter-spica.ts.net:11434",
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
    if text == "" or line == "":
        return "", "", "No information given"
    try:
        ex_prompt = (
            f"The following java snippet contains the vulnerability "
            f"`{hotspot['message']}` with a {hotspot['vulnerabilityProbability']} probability. "
            f"\nHere is the vulnerable code:\n"
            f"Vulnerable line:\n```java\n{line}\n```"
            f"\n\nParent section of the vulnerable line:\n```java\n{text}\n```"
            f"\n\nCurrent imports:\n```java\n{imp}\n```"
            f"Explain what fixes are going to be made and why they fix the vulnerability or why the vulnerability is a false positive."
            f"Your response should only include the explanation of what is going to be fixed, do not include any imports."
        )

        patch_prompt = """
    Now implement your fix into the `parent section`.
    Your response should only contain valid java code and must be formatted in a markdown codeblock.
    If no changes are needed to the `parent section`, reply only with `n/a`.
    """

        imp_prompt = """
    Now you need to list any import statement that would be needed for your implementation.
    Your response should only contain valid java imports and must be formatted in a markdown codeblock.
    If no new imports are needed, reply only with `n/a`.
    """

        stream = oclient.chat(
            model="llm-coder",
            messages=[
                {
                    "role": "user",
                    "content": ex_prompt,
                }
            ],
            stream=True,
        )
        ex_response = []
        for chunk in stream:
            ex_response.append(chunk.message.content)
        exp_text = "".join(ex_response)
        print(f"Explanation:\n{exp_text}")

        stream = oclient.chat(
            model="llm-coder",
            messages=[
                {
                    "role": "user",
                    "content": ex_prompt,
                },
                {
                    "role": "system",
                    "content": exp_text,
                },
                {
                    "role": "user",
                    "content": patch_prompt,
                },
            ],
            stream=True,
        )
        patch_response = []
        for chunk in stream:
            patch_response.append(chunk.message.content)
        patch = "".join(patch_response)
        assert "```java" in patch, f"Bad markdown format {patch}"
        assert "```" in patch, f"Bad markdown format {patch}"
        fixed_parent_text = (patch
                             .split("```java")[-1]
                             .split("```")[0]
                             .strip())
        print(f"Patch:\n{fixed_parent_text}")

        stream = oclient.chat(
            model="llm-coder",
            messages=[
                {
                    "role": "user",
                    "content": ex_prompt,
                },
                {
                    "role": "system",
                    "content": exp_text,
                },
                {
                    "role": "user",
                    "content": patch_prompt,
                },
                {
                    "role": "system",
                    "content": patch,
                },
                {
                    "role": "user",
                    "content": imp_prompt,
                },
            ],
            stream=True,
        )
        imp_response = []
        for chunk in stream:
            imp_response.append(chunk.message.content)
        imp = "".join(imp_response)
        if "n/a" in imp:
            fixed_import_text = ""
        else:
            assert "```java" in imp, f"Bad markdown format: {imp}"
            assert "```" in imp, f"Bad markdown format: {imp}"
            fixed_import_text = (imp
                                 .split("```java")[-1]
                                 .split("```")[0]
                                 .strip())
        print(f"Imp:\n{fixed_import_text}")

        if not fixed_parent_text or not fixed_import_text or not exp_text:
            print(
                f"Text was empty: "
                f"P:{bool(fixed_parent_text)} "
                f"I:{bool(fixed_import_text)} "
                f"E:{bool(exp_text)}"
            )
            return text, imp, "No changes were made."

        return str(fixed_parent_text), str(fixed_import_text), str(exp_text)
    except:
        print(f"Unexpected error: {sys.exc_info()[0]}")
        return text, imp, "No changes were made."


def splice_fix(hotspot: dict, patch: str, imports: str) -> None:
    """
    Splices the patch into the file
    :param hotspot: the hotspot to patch
    :param patch: the patch to inject
    :param imports: the imports to inject
    :return: ...
    """

    file_path = hotspot["component"].split(":")[1]
    file_path = os_ify_path(os.path.join(root_dir, file_path))
    with open(file_path) as f:
        text = f.read()

    lines = text.split("\n")
    start_line, end_line = curly_context(lines, hotspot["line"])

    before_lines = lines[:start_line]
    after_lines = lines[(end_line + 1) :]
    patched_lines = patch.split("\n")
    patched_lines.insert(0, "// New code begins below")
    patched_lines.append("// New code ends here")

    before_lines.extend(patched_lines)
    lines = before_lines
    lines.extend(after_lines)

    file = "\n".join(before_lines) + "\n".join(after_lines)

    # Unique set of import statements
    imps = set()
    for line in imports.split("\n"):
        imps.add(line)
    for line in lines:
        if line.strip().startswith("import"):
            imps.add(line)

    lines = file.split("\n")
    lines = list(filter(lambda line: not line.strip().startswith("import"), lines))
    print(f"Combined imports:\n{imps}")
    if "package " in file:
        for i in range(len(lines)):
            line = lines[i]
            if line.strip().startswith("package"):
                before_lines = lines[:(i + 1)]
                after_lines = lines[(i + 1):]
                lines = before_lines + list(imps) + after_lines
                break
    else:
        lines = list(imps) + lines

    file = "\n".join(lines)
    print(file)

    #return file
    try:
        with open(file_path, "w") as f:
            f.write(file)
            print("Updated file: " + file_path)
    except Exception as err:
        print(f"Failed to update file: {file_path}\n{err}\n{file}")

random.shuffle(hotspots)

issues = []
times = []
for i in range(min(len(hotspots), 10)):
    spot = hotspots[i]
    try:
        tStart = time.time()
        patched, imps, explanation = get_fix(client, spot)
        # fun_text, vuln_line, imports = parse_spot(spot)
        # patched, imps, explanation = fun_text, imports, "Things were maybe done"
        tDuration = time.time() - tStart
        print(f"Patch ({tDuration}s):\n{explanation}")
        print(f"----\nFixed File:\n{splice_fix(spot, patched, imps)}")
        times.append(tDuration)
        issues.append((f"{spot['key']}-{spot['component'].split('/')[-1]}:{spot['line']}", explanation))
        p = subprocess.Popen(
            f"git commit . -m \"Patched {spot['key']}\"",
            shell=True,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        p.communicate()
    except Exception as err:
        print(f"Failed to patch issue: {spot['key']}\n{err}\n{spot}")

print(
    f"\n\n----\nAverage response time: {sum(times) / len(times)}s,"
    f" Min: {min(times)}, Max: {max(times)}\n"
    f"Commiting changes"
)

# push
p = subprocess.Popen(
    ["git", "push", "origin", branch],
    stdout=sys.stdout,
    stderr=sys.stderr,
)
p.communicate()
print("Changes pushed.")

pr_create = (
    f"az repos pr create "
    f"--organization {os.environ['AZURE_ORG']} "
    f"--project {os.environ['AZURE_PROJECT']} "
    f"--repository {repo['name']} "
    f"--source-branch {branch} "
    f"--target-branch main "
    f"--title \"PR to Patch {len(issues)} Issue(s)\" "
    f"--description \"# Patched {len(issues)} Issue(s):\" " +
    " ".join(['\"- ' + i[0] + '\"' for i in issues])
)
print(pr_create)
p = subprocess.check_output(
    pr_create,
    shell=True,
)
p = json.loads(p.decode())
print(json.dumps(p, indent=2))
pr_uri = p["url"] + "/threads?api-version=7.1"


for i in issues:
    exp = f"# {i[0]}" + "\n" + i[1]
    body = {
        "comments": [
            {
                "parentCommentId": 0,
                "content": exp,
                "commentType": 1
            }
        ],
        "status": 1
    }

    try:
        resp = requests.post(
            pr_uri,
            json=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {os.environ['AZURE_DEVOPS_EXT_PAT']}"
            },
        )
        print(resp.json())
    except Exception as err:
        print(f"Failed to post issues: {err}")
