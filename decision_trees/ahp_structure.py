from __future__ import annotations

class AhpNode:
    
    def __init__(self, id : str):
        self.id = id
        self.children = []
        self.comparisons = {}

    def add_child(self, child: AhpNode):
        self.children.append(child)
    
    def add_comparison(self, siblingId : str, weight : float):
        self.comparisons[siblingId] = weight
    
    def get_children(self):
        return self.children

class AhpTree:
    
    def __init__(self):
        self.algorithm = "ahp"
        self.version = 1
        self.nodes = {}
        self.nodes['children'] = []

    def add_child(self, child: AhpNode):
        self.nodes['children'].append(child)

    def get_children(self):
        return self.nodes['children']
