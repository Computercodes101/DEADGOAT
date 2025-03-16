"""
alksdjdh
"""
import json
import os
#Unfamiliar with the "flows" section, sorry
hotspots = json.loads(open('../../example_hotspots.json', 'r').read())["hotspots"]

#print(len(hotspots), hotspots[0])

#pretty_hotdump = json.dumps(hotspots[0], indent=4)
#print(pretty_hotdump) #visual assistance

#components = set()
#for hot in hotspots:
#    components.add(hot["component"][:hot["component"].index('/', hot["component"].index('/')+1)])
#print(components) # THIS RETURNS {'.html', '.java', '.js'}

#TODO: Grab the actual line of vulnerable code from each hotspot.
errorFileContents = {}

# webGoatDir = os.fsencode("../test/java/org/owasp/webgoat/")
# print(os.listdir(webGoatDir))
# for subDir in os.listdir(webGoatDir):
#     if subDir == b'WithWebGoatUser.java': continue
#     subDirPath = "../test/java/org/owasp/webgoat/" + os.fsdecode(subDir) + "/"
#     for folder in os.listdir(os.fsencode(subDirPath)):
#         if os.fsdecode(folder).__contains__("."): continue
#         folderPath = os.fsdecode(subDirPath) + os.fsdecode(folder) + "/" #eg. ../test/java/org/owasp/webgoat/webwolf/user/
#         for file in os.listdir(os.fsencode(folderPath)):
#             fileName = os.fsdecode(file) #eg. "UserServiceTest.java"
#             if fileName.endswith(".html") or fileName.endswith(".java") or fileName.endswith(".js"):
#                 with open(folderPath + fileName, 'r') as f:
#                     errorFileContents[fileName] = f.readlines() #reads every code file in the folders
#             elif not(fileName.__contains__(".")): #catch for subfolders
#                 realFolderPath = folderPath + fileName + "/"
#                 for realFile in os.listdir(os.fsencode(realFolderPath)):
#                     realFileName = os.fsdecode(realFile)
#                     if realFileName.endswith(".html") or realFileName.endswith(".java") or realFileName.endswith(".js"):
#                         with open(realFolderPath + realFileName, 'r') as f:
#                             errorFileContents[realFileName] = f.readlines()

#This should read every relevant code file into errorFileContents.
for subdir, dirs, files in os.walk("..\\"):
    for file in files:
        if file.endswith((".html", ".js", ".java")):
            isInHotspot = False
            for hot in hotspots:
                hotFileName = hot["component"][hot["component"].rindex('/')+1:]
                if file == hotFileName:
                    isInHotspot = True
                    break
            if isInHotspot:
                filepath = os.path.join(subdir, file)
                with open(filepath, 'r') as f:
                    errorFileContents[file] = f.readlines()

#print(errorFileContents["DeserializeTest.java"][58])

#This should add a new key-pair to each hotspot that contains the associated vulnerable lines.
for hot in hotspots:
    fileName = hot["component"][hot["component"].rindex('/')+1:]
    startLineIndex = hot["textRange"]["startLine"]-1 #FYI, 0 indexing stuff means the actual index needs to shift by 1
    endLineIndex = hot["textRange"]["endLine"]-1
    hot["vulnerableLines"] = errorFileContents[fileName][startLineIndex:endLineIndex+1]
print("Success!")
print(hotspots[0]["vulnerableLines"]) #We are still left with whitespace. This can be modified as you see fit.

