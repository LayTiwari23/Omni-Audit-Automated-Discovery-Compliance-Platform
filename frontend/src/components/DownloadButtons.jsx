// src/components/DownloadButtons.jsx
import { useState } from "react";
import {
  DocumentReportIcon,
} from "@heroicons/react/outline";
import { downloadReport } from "../api/api";
import Button from "./ui/Button";
import Spinner from "./ui/Spinner";
import { Card, CardContent } from "./ui/Card";
import toast from "react-hot-toast";

export default function DownloadButtons({ reportId, disabled = false }) {
  const [loading, setLoading] = useState(false);

  const handleDownload = async () => {
    setLoading(true);
    try {
      await downloadReport(reportId);
      toast.success("Download started");
    } catch (e) {
      toast.error(e.message || "Download failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className="border border-gray-200">
      <CardContent className="p-6">
        <div className="flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="flex items-center gap-4">
            <div className="flex-shrink-0 w-16 h-16 rounded-2xl bg-blue-50 flex items-center justify-center text-blue-600 shadow-sm border border-blue-100">
              <DocumentReportIcon className="w-8 h-8" />
            </div>
            <div>
              <h3 className="text-xl font-bold text-gray-900 mb-1">Professional PDF Report</h3>
              <p className="text-sm text-gray-500 max-w-md">
                {disabled
                  ? "Your comprehensive security assessment report will be available once the scan is complete."
                  : "Download a detailed assessment report including executive summary, risk distribution, and technical evidence."}
              </p>
            </div>
          </div>
          
          <Button
            variant="primary"
            size="lg"
            onClick={handleDownload}
            disabled={disabled || loading}
            className="w-full md:w-auto px-10 py-4 shadow-lg shadow-blue-100 hover:shadow-xl hover:shadow-blue-200 transition-all transform hover:scale-[1.02] active:scale-[0.98]"
          >
            {loading ? (
              <>
                <Spinner size="sm" className="mr-2" />
                Preparing Report…
              </>
            ) : (
              <>
                <DocumentReportIcon className="w-5 h-5 mr-2" />
                Download PDF
              </>
            )}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
