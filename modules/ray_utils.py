"""
Ray Utilities

Inspired by:
https://github.com/honnibal/spacy-ray/pull/1/files#diff-7ede881ddc3e8456b320afb958362b2aR12-R45

Modified from:
https://docs.ray.io/en/latest/auto_examples/progress_bar.html
"""
from __future__ import annotations
from asyncio import Event
from typing import Any, Callable, List, Mapping, Optional, Tuple
from ray.actor import ActorHandle
from tqdm import tqdm  # type: ignore
import ray


@ray.remote
class ProgressBarActor:
    """
    Utility class for ProgressBar
    """

    counter: int
    delta: int
    event: Event

    def __init__(self) -> None:
        self.counter = 0
        self.delta = 0
        self.event = Event()

    def update(self, num_items_completed: int) -> None:
        """Updates the ProgressBar with the incremental
        number of items that were just completed.
        """
        self.counter += num_items_completed
        self.delta += num_items_completed
        self.event.set()

    async def wait_for_update(self) -> Tuple[int, int]:
        """Blocking call.

        Waits until somebody calls `update`, then returns a tuple of
        the number of updates since the last call to
        `wait_for_update`, and the total number of completed items.
        """
        await self.event.wait()
        self.event.clear()
        saved_delta = self.delta
        self.delta = 0
        return saved_delta, self.counter

    def get_counter(self) -> int:
        """
        Returns the total number of complete items.
        """
        return self.counter


class ProgressBar:
    """
    Ray-compatible progressbar
    """

    progress_actor: ActorHandle
    total: int
    description: str
    pbar: tqdm

    def __init__(self, total: int, description: str = "") -> None:
        """
        Ray actors don't seem to play nice with mypy, generating
        a spurious warning for the following line,
        which we need to suppress. The code is fine.
        """
        # pylint: disable=no-member
        self.progress_actor = ProgressBarActor.remote()  # type: ignore
        self.total = total
        self.description = description

    @property
    def actor(self) -> ActorHandle:
        """Returns a reference to the remote `ProgressBarActor`.

        When you complete tasks, call `update` on the actor.
        """
        return self.progress_actor

    def print_until_done(self) -> None:
        """Blocking call.

        Do this after starting a series of remote Ray tasks, to which you've
        passed the actor handle. Each of them calls `update` on the actor.
        When the progress meter reaches 100%, this method returns.
        """
        # https://stackoverflow.com/questions/41707229/tqdm-printing-to-newline
        pbar = tqdm(desc=self.description, total=self.total, position=0, leave=True)
        while True:
            delta, counter = ray.get(self.actor.wait_for_update.remote())
            pbar.update(delta)
            if counter >= self.total:
                pbar.close()
                return


@ray.remote
def aux(
    task_handler: Callable,
    task: Tuple,
    store: Mapping,
    actor_id: Optional[Any] = None,
) -> Any:
    """Runs task handler on task, updates progressbar and finally returns the result"""

    result = task_handler(*task, **{key: ray.get(store[key]) for key in store})
    if actor_id is not None:
        actor_id.update.remote(1)  # type: ignore
    return result


def execute_with_ray(
    task_handler: Callable,
    tasks: List,
    store: Optional[Mapping] = None,
    progress_bar: bool = True,
) -> List:
    """Apply task_handler to list of tasks.

    Tasks are processed in parallel with pipelining.
    progress_bar : If set to True, shows progressbar.
    """
    if len(tasks) == 0:
        return []

    if progress_bar:
        # Progressbar Ray Actor
        num_ticks = len(tasks)
        pbar = ProgressBar(num_ticks)
        actor = pbar.actor
        actor_id = ray.put(actor)

    tasks_pre_launch = [
        aux.remote(
            task_handler,
            task,
            store={key: ray.put(store[key]) for key in store}
            if store is not None
            else {},
            actor_id=actor_id if progress_bar else None,
        )
        for task in tasks
    ]

    # Opens progressbar until all tasks are completed
    if progress_bar:
        pbar.print_until_done()

    # Processes tasks with pipelining
    results = []
    while len(tasks_pre_launch) != 0:
        done_id, tasks_pre_launch = ray.wait(tasks_pre_launch)
        results.append(ray.get(done_id[0]))

    return results
