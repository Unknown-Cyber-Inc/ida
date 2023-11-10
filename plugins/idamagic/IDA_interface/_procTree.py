"""
Methods and classes in the MAGICPluginScrClass related to populating the
procedure table.
"""

import json
import logging
import traceback
import ida_kernwin

from cythereal_magic.rest import ApiException
from PyQt5.QtWidgets import QTableWidgetItem
from ..helpers import create_proc_name

logger = logging.getLogger(__name__)

class _ScrClassMethods:
    """
    Methods in the MAGICPluginScrClass related to populating the procedure table
    """

    def populate_proc_table(self, procedureInfo):
        """populates the procedures table with recieved procedures

        @param resources: dict containing procedures return request
        """
        self.image_base = int(procedureInfo.image_base, 16)
        for proc in procedureInfo.procedures:
            proc_name = create_proc_name(proc)

            proc_info = [
                proc_name,
                str(proc.occurrence_count),
                proc.status,
                ("0" if not proc.notes else str(len(proc.notes))),
                ("0" if not proc.tags else str(len(proc.tags))),
            ]
            # insert blank row
            self.proc_table.insertRow(self.proc_table.rowCount())
            # place data in column slots of blank row
            for col, info in enumerate(proc_info):
                col_item = QTableWidgetItem(info)
                self.proc_table.setItem(
                    self.proc_table.rowCount() - 1, col, col_item
                )
            # Set the row's address column .data() to proc object
            row = self.proc_table.rowCount() - 1
            row_addr_col = self.proc_table.item(row, 0)
            # QtTableWidgetItem.setData(role: int, value: object)
            row_addr_col.setData(1, proc)

            # add node to dict to avoid looping through objects in PluginScrHooks
            start_ea = ida_kernwin.str2ea(proc.start_ea)
            proc_node_row = self.proc_table.rowCount()
            self.procedureEADict_unbased[start_ea] = proc_node_row -1
            start_ea = start_ea + self.image_base
            self.procedureEADict[start_ea] = proc_node_row -1

    def pushbutton_click(self):
        """What to do when the 'Get Procedures' button is clicked.

        GET from procedures and list all procedures associated with file.
        """
        self.proc_table.reset_table()
        genomics_read_mask = (
            "cfg,start_ea,is_library,status,procedure_hash,notes,tags,"
            + "occurrence_count,strings,api_calls,procedure_name"
        )
        order_by = "start_ea"

        try:
            response = self.ctmfiles.list_file_genomics(
                binary_id=self.hashes["version_hash"],
                read_mask=genomics_read_mask,
                order_by=order_by,
                no_links=True,
                page_size=0,
                async_req=True,
            )
            response = response.get()
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            print("No procedures could be gathered.")
            for error in json.loads(exp.body).get("errors"):
                logger.info(error["reason"])
                print(f"{error['reason']}: {error['message']}")
            return None
        except Exception as exp:
            logger.debug(traceback.format_exc())
            print("Unknown Error occurred")
            print(f"<{exp.__class__}>: {str(exp)}")
            print(traceback.format_exc())
            # exit if this call fails so user can retry
            # (this func always returns None anyway)
            return None
        else:
            if 200 <= response.status <= 299:
                print("Procedures gathered successfully.")
                self.populate_proc_table(response.resource)
                if self.hashes["version_hash"] != self.hashes["loaded_sha1"]:
                    self.sync_warning.show()
            else:
                print("Error gathering Procedures.")
                print(f"Status Code: {response.status}")
                print(f"Error message: {response.errors}")
