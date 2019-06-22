/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Creates a selection in the current program consisting of the sum
//of all function bodies.
//@category Selection

import java.io.IOException;
import java.util.*;     // Map & List

import java.lang.Math;
import java.lang.Object;
import java.text.DecimalFormat;

import ghidra.program.model.listing.*;
import ghidra.program.model.block.*;    //CodeBlock && CodeBlockImpl
import ghidra.program.model.address.*;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.scalar.Scalar;

import ghidra.program.model.mem.*;

import ghidra.program.database.*;
import ghidra.program.database.function.*;
import ghidra.program.database.code.*;


import ghidra.util.task.TaskMonitor;    // TaskMonitor
import ghidra.app.script.GhidraScript;


public class SymbolicVSA extends GhidraScript {
    private Program program;
    private Listing listing;

    /* Calculate the address space of code segment */
    AddressSet getCodeSegmentAddresRange() {
        MemoryBlock[] blocks;
        Address start, end;
        long startVM, endVM;
        Address startF = null, endF = null;

        blocks = program.getMemory().getBlocks();
        startVM = 10;    // startVM = (unsigned long) -1
        endVM = 0;

        for (MemoryBlock blk: blocks) {
            /* An ELF file always has several code sections. If yes, we assume they are layed continuously */
            if (!(blk.isExecute() && blk.isInitialized() && blk.isLoaded())) continue;

            start = blk.getStart();
            end = blk.getEnd();

            if (startVM > endVM) {  // This means we find the first code section
                startVM = start.getOffset();
                endVM = end.getOffset();
                startF = start;
                continue;
            }

            /* considering code alignment, default to 16 bytes */
            if (endVM < end.getOffset() && start.getOffset() <= (endVM + 15 >> 4 << 4)) {
                endVM = end.getOffset();
                endF = end;
            }
            else {
                /* warning ? */
                println(String.format("87: Non-continuous section: %s: 0x%x - 0x%x", blk.getName(), start.getOffset(), end.getOffset()));
            }
        }

        if (startF == null || endF == null) {
            throw new IllegalArgumentException("Faile to find code segment");
        }
        return new AddressSet(startF, endF);
    }

    @Override
    public void run() {
        program = state.getCurrentProgram();
        listing = program.getListing();


        /* travese all functions */
        AddressSet codesegRng = getCodeSegmentAddresRange();
        Address startVM = codesegRng.getMinAddress();
        Address endVM = codesegRng.getMaxAddress();

        FunctionIterator iter = listing.getFunctions(true);

        while (iter.hasNext() && !monitor.isCancelled()) {
            Function f = iter.next();
            String fname = f.getName();
            Address f_startVM, f_endVM;

            f_startVM = f.getBody().getMinAddress();
            f_endVM = f.getBody().getMaxAddress();

            /* skip all functions out the address space of current segment */
            if (f_startVM.getOffset() < startVM.getOffset() ||  f_endVM.getOffset() > endVM.getOffset()) continue;

            // Entry-point
            if (f.getEntryPoint().getOffset() != 0x400546)
                continue;

            println("Function Entry: " + f.getEntryPoint());
            println("Function Name: " + f.getName());


            //FunctionSMAR smar = new FunctionSMAR(arch, program, listing, f, monitor);
            //smar.doRecording();

            //Map<Long, Map<String, Set<String>>> smart = smar.getSMARTable();

            //println(smart.toString());
        }
    }


    boolean mergeVSATables() {
        //for (BlockSMAR blk: m_blocks) {
        //Map<String, Set<String>> table = blk.getVSATable();

        /* merge two tables */
        //}
        return true;
    }

    boolean structAnalysis() {
        return true;
    }
}
