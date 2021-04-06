import time

class ChronoTimer():

    def __init__(self):
        self.start_time_exploit_scraping = -1
        self.start_time_tree_build = -1
        self.start_time_constraints = -1

        self.total_time_exploit_scraping = 0
        self.total_time_tree_build = 0
        self.total_time_constraints = 0

    def start_exploit_scraping(self):
        self.start_time_exploit_scraping = time.time()

    def stop_exploit_scraping(self):
        self.total_time_exploit_scraping += time.time() - self.start_time_exploit_scraping

    def start_tree_build(self):
        self.start_time_tree_build = time.time()

    def stop_tree_build(self):
        self.total_time_tree_build += time.time() - self.start_time_tree_build

    def start_constraints(self):
        self.start_time_constraints = time.time()

    def stop_constraints(self):
        self.total_time_constraints += time.time() - self.start_time_constraints

    def get_exploit_scraping_time(self):
        return self.total_time_exploit_scraping

    def get_tree_build_time(self):
        return self.total_time_tree_build

    def get_constraints_time(self):
        return self.total_time_constraints
