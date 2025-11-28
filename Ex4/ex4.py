# Librairies
import subprocess

def scan(filename : str, create_filename : str):
    """
        Abstract : Scan a file and save results

        Input : 
        - filename (str) : Filename to scan
        - create_filename (str) : Filename to store results

        Output : None
    """
    scan_command = (f"bandit -r {filename}").split(" ") # Trivy cannot scan python object, so we use bandit instead
    output = subprocess.run(scan_command, capture_output=True, text=True, encoding='utf-8', errors='replace')

    with open(f"./{create_filename}", 'w') as file:
        file.write(output.stdout)

if __name__ == "__main__":
    file_to_scan = ["../Ex1/ex1.py", "../Ex2/ex2.py", "../Ex3/ex3_1.py", "../Ex3/ex3_2.py", "../Ex3/ex3_3.py", "../Ex4/ex4.py"]
    for file in file_to_scan:
        scan(file, f"results_scan_{file[7:-3]}.txt")