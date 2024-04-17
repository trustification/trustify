import {
  downloadAdvisoryById,
  downloadCVEById,
  downloadSBOMById,
} from "@app/api/rest";
import { saveAs } from "file-saver";

export const useDownload = () => {
  const downloadAdvisory = (id: string, filename?: string) => {
    downloadAdvisoryById(id).then((response) => {
      saveAs(new Blob([response.data]), filename || `${id}.json`);
    });
  };

  const downloadCVE = (id: string, filename?: string) => {
    downloadCVEById(id).then((response) => {
      saveAs(new Blob([response.data]), filename || `${id}.json`);
    });
  };

  const downloadSBOM = (id: string, filename?: string) => {
    downloadSBOMById(id).then((response) => {
      saveAs(new Blob([response.data]), filename || `${id}.json`);
    });
  };

  return { downloadAdvisory, downloadCVE, downloadSBOM };
};
