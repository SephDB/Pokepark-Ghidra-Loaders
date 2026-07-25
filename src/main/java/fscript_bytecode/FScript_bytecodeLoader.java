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
package fscript_bytecode;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import fscript_bytecode.structures.Header;
import fscript_bytecode.structures.SymbolTableEntry;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Provide class-level documentation that describes what this loader does.
 */
public class FScript_bytecodeLoader extends AbstractProgramWrapperLoader {

	@Override
	public String getName() {

		// Name the loader.  This name must match the name of the loader in the .opinion files.
		
		return "FScript Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// Examine the bytes in 'provider' to determine if this loader can load it.  If it 
		// can load it, return the appropriate load specifications.
		if(new BinaryReader(provider, false).readInt(0) == 0x20) {
			loadSpecs.add(new LoadSpec(this,0, new LanguageCompilerSpecPair("fscript:BE:32:default", "default"), true));
		}

		return loadSpecs;
	}

	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		FileBytes bytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		BinaryReader reader = new BinaryReader(provider, false);
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		
		try {
			Address base = api.toAddr(0x50000);
			MemoryBlock ROM = program.getMemory().createInitializedBlock("ROM", base, bytes, 0, 0x20, false);
			ROM.setPermissions(true, false, false);
			
			Header header = new Header(reader);
			
			api.createData(base, header.toDataType());
			
			MemoryBlock CODE = program.getMemory().createInitializedBlock("TEXT", base.add(header.instruction_offset), bytes, header.instruction_offset, header.symbol_table_offset - header.instruction_offset,false);
			CODE.setPermissions(true, false, true);
			MemoryBlock SYM = program.getMemory().createInitializedBlock("SYM", base.add(header.symbol_table_offset),bytes, header.symbol_table_offset, header.string_section_offset - header.symbol_table_offset, false);
			SYM.setPermissions(true, false, false);
			MemoryBlock STRINGS = program.getMemory().createInitializedBlock("STRINGS", base.add(header.string_section_offset), bytes, header.string_section_offset, provider.length() - header.string_section_offset,false);
			STRINGS.setPermissions(true, false, false);
			
			RegisterValue val = new RegisterValue(program.getRegister("STR"), STRINGS.getStart().getOffsetAsBigInteger());
			
			program.getProgramContext().setRegisterValue(CODE.getStart(), CODE.getEnd(), val);
			
			api.createData(SYM.getStart(), new ArrayDataType(SymbolTableEntry.getDataType(), (int)SYM.getSize()/SymbolTableEntry.getDataType().getLength()));
			
			Address address = STRINGS.getStart();
			while(address.compareTo(STRINGS.getEnd()) < 0) {
				Data d = api.createAsciiString(address);
				address = address.addNoWrap(d.getLength());
			}
			
			reader.setPointerIndex(header.symbol_table_offset);
			while(reader.getPointerIndex() != header.string_section_offset) {
				SymbolTableEntry entry = new SymbolTableEntry(reader);
				var label = api.createLabel(base.add(entry.getPosition()), entry.getName(), true);
				api.addEntryPoint(label.getAddress());
			}
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	@Override
	protected void load(Program program, ImporterSettings settings) throws CancelledException, IOException {
		load(settings.provider(),settings.loadSpec(),settings.options(),program,settings.monitor(),settings.log());
	}
}
