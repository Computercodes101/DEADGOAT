"""
alksdjdh
"""
import json

hotspots = json.loads(open('../../example_hotspots.json', 'r').read())["hotspots"]

print(len(hotspots), hotspots[0])
