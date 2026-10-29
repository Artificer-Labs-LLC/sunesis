// ExportProgram.java - GhidraScript for the two-engines provider.
//
// Emits one JSON object per function (JSON Lines) describing the program
// Ghidra analyzed: identity, prototype, called functions, the Ghidra
// Function ID hash pair (computed by Ghidra's own FidService - the same
// code the Function ID analyzer uses), and optionally the decompiler's
// pseudocode.
//
// Usage (headless):
//   -postScript "ExportProgram.java" "<output.jsonl>" [decompile|nodecompile]
//
// Licensed under the Apache License, Version 2.0.
//@category TwoEngines

import java.io.File;
import java.io.PrintWriter;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.service.FidService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ExportProgram extends GhidraScript {

    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.toString();
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ExportProgram: missing output path argument");
            return;
        }
        boolean wantDecompile = args.length < 2 || !"nodecompile".equals(args[1]);

        DecompInterface decomp = null;
        if (wantDecompile) {
            decomp = new DecompInterface();
            decomp.openProgram(currentProgram);
        }
        FidService fid = new FidService();

        File out = new File(args[0]);
        // Append: one headless run may process several imported programs.
        try (PrintWriter w = new PrintWriter(
                new java.io.FileWriter(out, true))) {
            w.println("{\"program\":\"" + esc(currentProgram.getName())
                + "\",\"language\":\"" + esc(currentProgram.getLanguageID().toString())
                + "\",\"image_base\":\"" + esc(currentProgram.getImageBase().toString())
                + "\",\"kind\":\"header\"}");
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                Address ep = f.getEntryPoint();
                StringBuilder sb = new StringBuilder();
                sb.append("{\"kind\":\"function\"");
                sb.append(",\"address\":\"").append(ep.toString()).append("\"");
                sb.append(",\"name\":\"").append(esc(f.getName())).append("\"");
                sb.append(",\"size\":").append(f.getBody().getNumAddresses());
                sb.append(",\"thunk\":").append(f.isThunk());
                String proto = "";
                try { proto = f.getSignature().getPrototypeString(); } catch (Exception e) { /* keep empty */ }
                sb.append(",\"prototype\":\"").append(esc(proto)).append("\"");
                sb.append(",\"return_type\":\"")
                  .append(esc(f.getReturnType() != null ? f.getReturnType().getName() : ""))
                  .append("\"");
                // Function ID hashes (Ghidra FidService)
                try {
                    FidHashQuad hq = fid.hashFunction(f);
                    if (hq != null) {
                        sb.append(",\"fid_full_hash\":\"").append(hq.getFullHash()).append("\"");
                        sb.append(",\"fid_specific_hash\":\"").append(hq.getSpecificHash()).append("\"");
                    }
                } catch (Exception e) {
                    sb.append(",\"fid_error\":\"").append(esc(String.valueOf(e.getMessage()))).append("\"");
                }
                // Called functions (names as Ghidra knows them after analysis)
                sb.append(",\"calls\":[");
                try {
                    Set<Function> called = f.getCalledFunctions(monitor);
                    boolean first = true;
                    for (Function c : called) {
                        if (!first) sb.append(",");
                        first = false;
                        sb.append("\"").append(esc(c.getName())).append("\"");
                    }
                } catch (Exception e) { /* leave empty */ }
                sb.append("]");
                // Decompiled pseudocode
                if (wantDecompile) {
                    String c = null;
                    String err = null;
                    try {
                        DecompileResults res = decomp.decompileFunction(f, 60, monitor);
                        if (res != null && res.getDecompiledFunction() != null) {
                            c = res.getDecompiledFunction().getC();
                        } else if (res != null) {
                            err = res.getErrorMessage();
                        }
                    } catch (Exception e) {
                        err = String.valueOf(e.getMessage());
                    }
                    if (c != null) sb.append(",\"pseudocode\":\"").append(esc(c)).append("\"");
                    if (err != null) sb.append(",\"decompile_error\":\"").append(esc(err)).append("\"");
                }
                sb.append("}");
                w.println(sb.toString());
            }
        }
        if (decomp != null) decomp.dispose();
        println("ExportProgram: wrote " + out.getAbsolutePath());
    }
}
