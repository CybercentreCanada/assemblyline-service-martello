import os

import martello
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultOrderedKeyValueSection


class Martello(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)

    def start(self):
        self.log.info("Starting Martello")
        self.model = martello.PredictiveModel()
        self.outfile = self.model.outfile

    def execute(self, request: ServiceRequest):
        request.result = Result()

        self.model.outfile = os.path.join(self.working_directory, self.outfile)
        self.model.scanfile(request.file_path)

        if self.model.fileProba is None:
            return

        res = ResultOrderedKeyValueSection("File analysis")
        res.add_item("Maliciousness", self.model.fileProba)
        if self.model.fileProba >= self.config.get("malicious_thr", 0.95):
            res.set_heuristic(2)
        elif self.model.fileProba >= self.config.get("suspicious_thr", 0.8):
            res.set_heuristic(1)
        elif self.model.fileProba <= self.config.get("benign_thr", 0.2):
            res.set_heuristic(3)
        request.result.add_section(res)
