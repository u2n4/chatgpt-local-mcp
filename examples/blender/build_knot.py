from collections import Counter
import json
import math
from pathlib import Path
import bpy
from mathutils import Vector

bpy.ops.wm.read_factory_settings(use_empty=True)
rings, sides = 720, 24
p, q = 3, 5

def center(t):
    r = 2.35 + .78 * math.cos(q*t)
    return Vector((r*math.cos(p*t), r*math.sin(p*t), .78*math.sin(q*t)))

vertices, faces = [], []
for i in range(rings):
    t = 2*math.pi*i/rings
    point = center(t)
    tangent = (center(t+1e-4)-center(t-1e-4)).normalized()
    trial = Vector((point.x, point.y, 0)).normalized()
    v = (trial - tangent*trial.dot(tangent)).normalized()
    w = tangent.cross(v).normalized()
    radius = .18 + .035 * math.cos(9*t)
    for j in range(sides):
        phi = 2*math.pi*j/sides
        vertices.append(tuple(point + radius*(math.cos(phi)*v + math.sin(phi)*w)))
        a, b = i*sides+j, i*sides+(j+1)%sides
        c, d = ((i+1)%rings)*sides+(j+1)%sides, ((i+1)%rings)*sides+j
        faces.append((a, b, c, d))

mesh = bpy.data.meshes.new("Periodic 3-5 knot")
mesh.from_pydata(vertices, [], faces)
mesh.update()
assert not mesh.validate(), "generated topology needed repair"
obj = bpy.data.objects.new("Torus knot 3-5", mesh)
bpy.context.collection.objects.link(obj)

palette = [(0.083, .31, .54, 1), (.10, .49, .51, 1), (.66, .33, .11, 1)]
for i, color in enumerate(palette):
    material = bpy.data.materials.new(f"Knot enamel {i+1}")
    material.diffuse_color = color
    obj.data.materials.append(material)
edge_counts = Counter()
for poly in mesh.polygons:
    assert poly.area > 1e-8
    poly.use_smooth = True
    poly.material_index = (poly.index // sides // 60) % len(palette)
    ids = list(poly.vertices)
    edge_counts.update(tuple(sorted((a,b))) for a,b in zip(ids,ids[1:]+ids[:1]))
stats = {"vertices":len(mesh.vertices),"edges":len(edge_counts),"quads":len(mesh.polygons),
         "euler":len(mesh.vertices)-len(edge_counts)+len(mesh.polygons),
         "manifold":set(edge_counts.values()) == {2}}
assert stats == {"vertices":17280,"edges":34560,"quads":17280,"euler":0,"manifold":True}, stats
bpy.context.view_layer.objects.active = obj
obj.select_set(True)
bpy.ops.wm.save_as_mainfile(filepath=str(Path("knot.blend").resolve()))
bpy.ops.export_scene.gltf(filepath=str(Path("knot.glb").resolve()), export_format="GLB", use_selection=True)
assert Path("knot.glb").read_bytes()[:4] == b"glTF"
Path("geometry.json").write_text(json.dumps(stats,indent=2),encoding="utf-8")
print("BLENDER_GEOMETRY_OK",json.dumps(stats),flush=True)
