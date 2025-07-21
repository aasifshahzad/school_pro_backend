import os
import shutil

def delete_pycache_folders(root_dir):
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for dirname in dirnames:
            if dirname == "__pycache__":
                pycache_dir = os.path.join(dirpath, dirname)
                shutil.rmtree(pycache_dir)
                print(f"Deleted: {pycache_dir}")

if __name__ == "__main__":
    # root_directory = input("Enter the root directory path: ")
    root_directory = "../"
    delete_pycache_folders(root_directory)
    print("All __pycache__ folders have been deleted.")


#uv run C:\Users\LENOVO\Documents\GitHub\school-pro-backend\utils\del_pycache.py 