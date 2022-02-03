package org.owasp.benchmarkutils.score.parsers;

import java.util.HashMap;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class SnykCodejsonReader extends Reader {
    private static HashMap<String, Integer> categoryCWE = new HashMap<String, Integer>();

    public static boolean isSnykReport(final JSONObject json) {
        try {
            JSONArray runs = json.getJSONArray("runs");
            JSONObject tool = runs.getJSONObject(0).getJSONObject("tool");
            JSONObject driver = tool.getJSONObject("driver");
            JSONArray rules = driver.getJSONArray("rules");
            String name = null;
            int cwe = 0;
            for (int i = 0; i < rules.length(); i++) {
                name = rules.getJSONObject(i).getString("name");
                JSONArray cwes =
                        rules.getJSONObject(i).getJSONObject("properties").getJSONArray("cwe");
                cwe = Integer.parseInt(cwes.getString(0).substring(4));
                if (cwe > 0) {
                    categoryCWE.put(name, cwe);
                }
                categoryCWE.put(name, cwe);
            }

            return driver.has("name");
        } catch (Exception e) {
            return false;
        }
    }

    public TestSuiteResults parse(JSONObject obj) throws Exception {

        JSONArray arr;

        try {
            JSONArray runs = obj.getJSONArray("runs");
            arr = runs.getJSONObject(0).getJSONArray("results");
        } catch (JSONException e) {
            System.out.println(
                    "ERROR: Couldn't find 'results' element in Snyk Code JSON results."
                            + " Maybe not a Snyk Code JSON results file?");
            return null;
        }

        TestSuiteResults tr =
                new TestSuiteResults("Snyk Code", true, TestSuiteResults.ToolType.SAST);

        // If the filename includes an elapsed time in seconds (e.g., TOOLNAME-seconds.xml),
        // set the compute time on the score card.

        int numIssues = arr.length();
        for (int i = 0; i < numIssues; i++) {
            TestCaseResult tcr = parseSnykJSONFinding(arr.getJSONObject(i));
            if (tcr != null) {
                tr.put(tcr);
            }
        }

        return tr;
    }

    //    {
    //    	  "$schema":
    // "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    //    	  "version": "2.1.0",
    //    	  "runs": [
    //    	    {
    //    	      "tool": {
    //    	        "driver": {
    //    	          "name": "SnykCode",
    //    	          "semanticVersion": "1.0.0",
    //    	          "version": "1.0.0",
    //    	          "rules": [
    //    	            {
    //    	              "id": "java/InsecureCipher",
    //    	              "name": "InsecureCipher",
    //    	              "shortDescription": {
    //    	                "text": "Use of a Broken or Risky Cryptographic Algorithm"
    //    	              },
    //    	              "defaultConfiguration": {
    //    	                "level": "error"
    //    	              },
    private TestCaseResult parseSnykJSONFinding(JSONObject finding) {
        try {
            TestCaseResult tcr = new TestCaseResult();
            String ruleId = finding.getString("ruleId");
            ruleId = ruleId.substring(ruleId.lastIndexOf("/")).substring(1);
            JSONArray locations = finding.getJSONArray("locations");
            String filenameFull =
                    locations
                            .getJSONObject(0)
                            .getJSONObject("physicalLocation")
                            .getJSONObject("artifactLocation")
                            .getString("uri");
            String filename = filenameFull.substring(filenameFull.lastIndexOf("/")).substring(1);
            filename = filename.substring(0, filename.length() - 5);
            //            filename = filename.split(filename.lastIndexOf(".")).substring(0);
            if (filename.startsWith(BenchmarkScore.TESTCASENAME)) {
                tcr.setTestCaseName(filename);
                String testNumber = filename.substring(BenchmarkScore.TESTCASENAME.length());
                tcr.setNumber(Integer.parseInt(testNumber));
                tcr.setCategory(ruleId);
                tcr.setEvidence(filenameFull);
                tcr.setCWE(categoryCWE.get(ruleId));
            }
            return tcr;
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return null;
    }
}
