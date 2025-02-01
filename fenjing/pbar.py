from contextlib import contextmanager
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
)
console: Console = Console(stderr=True)

class PbarManager:
    def __init__(self):
        self.progress = Progress(
            TextColumn("[bold yellow]{task.description}", justify="left"),
            BarColumn(bar_width=None),
            "[bold yellow][progress.percentage]{task.percentage:>3.1f}%",
            "•",
            TimeRemainingColumn(),
            console=console,
        )

    @contextmanager
    def pbar(self, it, description):
        task_id = self.progress.add_task(description, start=False)
        self.progress.start_task(task_id)
        pbar = Pbar(self.progress, task_id, it)

        yield pbar

        self.progress.remove_task(task_id)


class Pbar:
    def __init__(self, progress: Progress, task_id, it):
        self.progress = progress
        self.task_id = task_id
        self.it_completed = 0
        self.progress.update(self.task_id, total=len(it))
        self.it = iter(it)

    def __iter__(self):
        return self

    def __next__(self):
        self.it_completed += 1
        self.progress.update(self.task_id, completed=self.it_completed)
        return next(self.it)

    def update(self, *args, **kwargs):
        return self.progress.update(self.task_id, *args, **kwargs)


pbar_manager = PbarManager()
