"""
alksdjdh
"""
import json
import os
import re

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
print(src_dir)
hotspots = json.loads(
    open(
        os.path.join(
            src_dir,
            "example_hotspots.json"
        ),
        'r'
    ).read()
)["hotspots"]

def parse_spot(spot: dict) -> str:
    """
    Given a hotspot as a dictionary, parse it and return the relevant code

    :param spot: The hotspot from the list
    :return: The text of the function containing the hotspot
    """

    file_path = spot["component"].split(":")[1]
    file_path = os_ify_path(os.path.join(root_dir, file_path))
    msg = spot["message"]
    blame = spot["author"]
    rule_key = spot["ruleKey"]
    with open(file_path, "r") as f:
        text = f.read()
    print(f"{msg} of type {rule_key} in {file_path} written by {blame}")

    function_regex = re.compile(
        r"\w*\s+"  # return type
        r"\w+\s*"  # function name
        r"\([^)]*\)\s*"  # function parameters
        r"\w*\s\w*\s"  # throw type
        r"\{",  # start of function
        re.MULTILINE,
    )
    lines = text.split("\n")
    start_line = 0

    # start at line "spot['line']" and work backwards until a line matches
    for i in range(spot["line"], -1, -1):
        line = lines[i]
        if len(function_regex.findall(line)) > 0:
            start_line = i
            break

    # work our way down the function until we have closed all parenthesis
    rem_paren = 0
    end_line = 0
    for i in range(start_line, len(lines)):
        line = lines[i]
        rem_paren += line.count("{")
        rem_paren -= line.count("}")
        if rem_paren == 0:
            end_line = i
            break

    end_line = min(end_line, len(lines) - 1)

    print(f"Violating function at line(s) {start_line + 1}:{end_line + 1}  \\/")

    fun_text = "\n".join(lines[start_line:end_line + 1])
    print(fun_text)

    return fun_text

parse_spot(hotspots[0])
