points = []
undone = []


def create_undo_point(label):
    points.append(label)
    return True


def perform_undo():
    undone.append(points.pop() if points else None)
    return True
