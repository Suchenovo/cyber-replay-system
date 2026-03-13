import os
from pathlib import Path

# 定义需要忽略的文件夹或文件（可根据需求增减）
IGNORE_LIST = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    ".idea",
    ".vscode",
    ".DS_Store",
}


def print_tree(directory, prefix=""):
    path = Path(directory)
    # 获取当前目录下的所有文件和文件夹，并过滤掉忽略名单
    items = sorted(
        [p for p in path.iterdir() if p.name not in IGNORE_LIST],
        key=lambda p: (not p.is_dir(), p.name.lower()),
    )

    count = len(items)
    for i, item in enumerate(items):
        is_last = i == count - 1
        # 根据是否是最后一个元素选择前缀
        connector = "└── " if is_last else "├── "

        # 打印当前文件/文件夹名称
        print(f"{prefix}{connector}{item.name}{'/' if item.is_dir() else ''}")

        # 如果是文件夹，则递归调用
        if item.is_dir():
            new_prefix = prefix + ("    " if is_last else "│   ")
            print_tree(item, new_prefix)


if __name__ == "__main__":
    # "." 表示当前目录，你也可以替换成绝对路径
    target_dir = "."

    # 打印根目录名称
    root_path = Path(target_dir).resolve()
    print(f"{root_path.name}/")

    # 开始递归
    print_tree(target_dir)
