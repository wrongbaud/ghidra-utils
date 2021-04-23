//PCode emulation script to brute force possible password combinations for Kong: King of Atlantis on the Game Boy Advance
//@author wrongbaud
//@category 
//@keybinding
//@menupath
//@toolbar

// Pulled from the example scripts in the included script manager 

import ghidra.app.script.GhidraScript;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;

import ghidra.app.emulator.*;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.pcode.emulate.EmulateExecutionState;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;
import ghidra.program.model.symbol.SymbolUtilities;
import java.util.function.Predicate;
public class KongBruteForce extends GhidraScript {
	
	private EmulatorHelper emuHelper;
	private Address mainFunctionEntry;
	private Address returnAddress;
	FileWriter fw;
	BufferedWriter bw;
	private Address getAddress(long offset) {
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}
	
	private void permute(byte[] a, int k) {
        int n = a.length;
        if (k < 1 || k > n)
            throw new IllegalArgumentException("Illegal number of positions.");
 
        int[] indexes = new int[n];
        int total = (int) Math.pow(n, k);
        byte[] passTest = {1,1,1,1,1,1,1};
        while (total-- > 0) {
            for (int i = 0; i < n - (n - k); i++)
                passTest[i] = a[indexes[i]];
            // Function Call to emulate goes here!
            try {
				passwd_crack(passTest);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
 
            for (int i = 0; i < n; i++) {
                if (indexes[i] >= n - 1) {
                    indexes[i] = 0;
                } else {
                    indexes[i]++;
                    break;
                }
            }
        }
    }
	
	public void passwd_crack(byte[] passwdVals) throws Exception{
		returnAddress = getAddress(0x82cccba);
		mainFunctionEntry = getSymbolAddress("check_password_1");
		// Obtain entry instruction in order to establish initial processor context
		Instruction entryInstr = getInstructionAt(mainFunctionEntry);
		// Instantiate our emulator helper
		emuHelper = new EmulatorHelper(currentProgram);
		char[] passwdChars = {'B','D','F','G','J','L','M'};
		SetupGBAMemory(passwdVals);
		emuHelper.writeRegister(emuHelper.getPCRegister(), mainFunctionEntry.getOffset());
		
		try {
			emuHelper.setBreakpoint(returnAddress);
			// Execution loop until return from function or error occurs
			while (!monitor.isCancelled()) {
				emuHelper.run(mainFunctionEntry, entryInstr, monitor);
				Address executionAddress = emuHelper.getExecutionAddress();
				//println(executionAddress.toString());
				if (monitor.isCancelled()) {
					println("Emulation cancelled");
					return;
				}
				if (executionAddress.equals(returnAddress)) {
					byte retVal = emuHelper.readRegister("r0").byteValue();
					if(retVal == 1) {
						String password = "";
						for(int x =0;x<7;x++) {
							password += passwdChars[passwdVals[x]-1];
						}
						println("Valid password found with password Vals: " + Arrays.toString(passwdVals) + "Password: "+password);
						bw.write(password);
						bw.newLine();
					}
					return;
				}
			}
		}
		finally {
			emuHelper.dispose();
		}
	}
	
	@Override
	protected void run() throws Exception {
	   DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");  
	   LocalDateTime now = LocalDateTime.now();  
		println("Kong Emulation Script Starting...");
		println(dtf.format(now)); 
		fw = new FileWriter("/home/wrongbaud/kong-passwords.txt", true);
		bw = new BufferedWriter(fw);
        byte[] chars = {1,2,3,4,5,6,7};
		permute(chars, 7);
		bw.close();
		println("Kong Emulation Script Ending...");
		now = LocalDateTime.now();  
		println(dtf.format(now)); 

	}
	
	
	private void SetupGBAMemory(byte [] passwdVals) {
		emuHelper.writeRegister(emuHelper.getStackPointerRegister(), 0x3007bc0);
		try {
			/*
			 * 
				r4             0x4                 4
				r5             0x30027e0           50341856
				r6             0x30027e8           50341864
				r7             0x3004654           50349652
				r8             0x0                 0
				r9             0x7                 7
				r10            0x3004653           50349651
				r11            0x0                 0
				r12            0x264               612
				sp             0x3007bc0           0x3007bc0
				lr             0x82caaff           137145087
				pc             0x82cc970           0x82cc970
				cpsr           0x6000003f          1610612799
			 */
			emuHelper.writeRegister("r0",passwdVals[0]);
			emuHelper.writeRegister("r1",passwdVals[1]);
			emuHelper.writeRegister("r2",passwdVals[2]);
			emuHelper.writeRegister("r3",passwdVals[3]);
			emuHelper.writeRegister("r4",4);
			emuHelper.writeRegister("r5",0x30027e0);
			emuHelper.writeRegister("r6",0x30027e8);
			emuHelper.writeRegister("r7",0x3004654);
			emuHelper.writeRegister("r8",0x0);
			emuHelper.writeRegister("r9",0x7);
			emuHelper.writeRegister("r10",0x3004653);
			emuHelper.writeRegister("r11",0x0);
			emuHelper.writeRegister("r12",0x264);
			emuHelper.writeRegister("sp", 0x3007bc0);
			emuHelper.writeRegister("lr", 0x82caaff);
			emuHelper.writeRegister("cpsr", 0x6000003f);
			emuHelper.writeRegister("CY", 0);
			emuHelper.writeStackValue(0, 4, passwdVals[4]);
			emuHelper.writeStackValue(4, 4, passwdVals[5]);
			emuHelper.writeStackValue(8, 4, passwdVals[6]);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	private Address getSymbolAddress(String symbolName) throws NotFoundException {
		Symbol symbol = SymbolUtilities.getLabelOrFunctionSymbol(currentProgram, symbolName,
			err -> Msg.error(this, err));
		if (symbol != null) {
			return symbol.getAddress();
		}
		throw new NotFoundException("Failed to locate label: " + symbolName);
	}
	

}


