import os
import pickle
import subprocess
import warnings

from string import Template

import numpy as np
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultOrderedKeyValueSection

# Ignore warnings from scikit
warnings.filterwarnings("ignore")

boost_lib = "./martello/boost"
topk_file = "./martello/bin/top100000-byCF-EmberHashes-n6.bin"
exec_file = "./martello/bin/martello-vectorizer"
scaler_file = "./martello/bin/scaler_ember-n6-bycf-trained-on-all-10AUG21.pkl"
sgd_file = "./martello/bin/sgd-ember-n6-bycf-trained-on-all-alpha0.1-l10.4.pkl"
thread_count = 1

CMD_FORMAT = Template(f"{exec_file} -f $file_path -k {topk_file} -n 6 -x 6 -t {thread_count} -o $output")


class Martello(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)

    def start(self):
        self.log.info("Starting martello")
        with open(topk_file) as f:
            self.K = np.fromfile(f, dtype=np.intc, count=1)[0]

        self.scaler = pickle.load(open(scaler_file, "rb"))
        self.sgd = pickle.load(open(sgd_file, "rb"))

    def execute(self, request: ServiceRequest):
        request.result = Result()

        if "LD_LIBRARY_PATH" in os.environ:
            os.environ["LD_LIBRARY_PATH"] = f"{os.environ['LD_LIBRARY_PATH']}:{boost_lib}"
        else:
            os.environ["LD_LIBRARY_PATH"] = boost_lib

        cmd = CMD_FORMAT.substitute(file_path=request.file_path, output="/tmp/outfile").split()
        proc = subprocess.run(cmd, capture_output=True)
        if proc.returncode != 0:
            raise Exception(f"Martello classifier returned {proc.returncode}")

        dtm_arr = np.memmap("/tmp/outfile.bin.part0", mode="r", dtype=np.intc).reshape(-1, self.K)
        dtm_scaled = self.scaler.transform(dtm_arr)
        predict_proba = list(self.sgd.predict_proba(dtm_scaled)[:, 1])[0]
        res = ResultOrderedKeyValueSection("File analysis")
        res.add_item("Maliciousness", predict_proba)
        if predict_proba >= self.config.get("malicious_thr", 0.95):
            res.set_heuristic(2)
        elif predict_proba >= self.config.get("suspicious_thr", 0.8):
            res.set_heuristic(1)
        elif predict_proba <= self.config.get("benign_thr", 0.2):
            res.set_heuristic(3)
        request.result.add_section(res)
