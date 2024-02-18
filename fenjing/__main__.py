from .cli import main as cli_main, RunFailed

def main():
    try:
        cli_main()
    except RunFailed:
        exit(1)

if __name__ == "__main__":
    main()
