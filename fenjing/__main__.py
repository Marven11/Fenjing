from .cli import main, RunFailed

if __name__ == "__main__":
    try:
        main()
    except RunFailed:
        exit(1)
