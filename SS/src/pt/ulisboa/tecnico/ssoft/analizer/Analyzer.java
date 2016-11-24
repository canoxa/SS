package pt.ulisboa.tecnico.ssoft.analizer;

import pt.ulisboa.tecnico.ssoft.analizer.SqliAnalyzer;
import pt.ulisboa.tecnico.ssoft.analizer.XssAnalyser;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class Analyzer {
	

	public static List<Pattern> patterns=new ArrayList<Pattern>();
	
	public static List<Pattern> patternsSQLI=new ArrayList<Pattern>();
	public static List<Pattern> patternsXSS=new ArrayList<Pattern>();
	
	public static Slice slice;
	
	private static String vulnCode = "";
	private static Map<String,String> sinkPointMap = new HashMap<>();

	public static void main(String[] args) throws IOException {
	
		if(args.length != 1)
	    {
	        System.out.println("Proper Usage is: java Analyzer filename");
	        System.exit(0);
	    }
		
		//Read the config file
		readConfFile();
		//Read the input file
		readFile(args[0]);
		//Check vulnerability in the code
		analysis();
		//isVuln();
	
	}


	public static void analysis()
	{
		boolean isvulnerableSQLI=false;
		boolean isvulnerableXSS=false;
		String res="";
		for (Pattern p : patterns)
			if(slice.isWhatType(p))
				res=p.vulnType;

	      
		if(res.contains("sql injection"))
		{

			for(Pattern p: patternsSQLI)
			{
				if(slice.isVulnurableSQLI(p))
				isvulnerableSQLI=true;
			}
		}
		if(res.contains("cross site scripting"))
		{
			for(Pattern p: patternsXSS)
			{
				if(slice.isVulnurableXSS(p))
				isvulnerableXSS=true;
			}
		}
	       	
		if(isvulnerableSQLI)
	        System.out.println("Vulnerability: SQL Injection");
		else if(isvulnerableXSS)
	        System.out.println("Vulnerability: Cross site scripting");

	}

	/*
	 * 	check vulnerability type
	 *  run validation check corresponding to type
	 *  
	 */
	private static void isVuln() {
		
		for (String sink : sinkPointMap.keySet()) {
			if (vulnCode.contains(sink)) {
				switch (sinkPointMap.get(sink)) {
				case "sqli":
					//TODO sqli validation check
					SqliAnalyzer.validate(vulnCode,sink);
					break;
				case "xss":
				//TODO xss validation check
					XssAnalyser.validate(vulnCode,sink);
				break;
				default:
					break;
				}
			}
		}
		
	}



	private static void readFile(String file) throws IOException {
		List<String> lines = Files.readAllLines(Paths.get(file), StandardCharsets.UTF_8);
		for (String string : lines) {
			vulnCode = vulnCode+ string;
		}
		slice=new Slice(lines);
	}


	//Reads configuration file to create Vulnerabilities list 
	private static void readConfFile() {
		
		FileReader fopen;
		BufferedReader br;
		List<String> vuln = new ArrayList<>();
		try {
			fopen = new FileReader("config.txt");
			br = new  BufferedReader(fopen);
			String line = null;
			
			
			while ((line = br.readLine()) != null) {
				
				if (line.trim().isEmpty()){			
					//fillPointMaps(vuln);
					Pattern s=new Pattern(vuln);

					patterns.add(s);

					//
					if(s.vulnType.contains("injection"))
					{
						patternsSQLI.add(s);
					}
					if(s.vulnType.contains("cross site scripting"))
					{
					patternsXSS.add(s);
					}
					//
					vuln.clear();
				}else{
					vuln.add(line);
				}	
				
			}
			
			Pattern p=new Pattern(vuln);
			patterns.add(p);

			if(p.vulnType.contains("injection"))
			{
				patternsSQLI.add(p);
			}
			if(p.vulnType.contains("cross site scripting"))
			{
			patternsXSS.add(p);
			}

			
		} catch (Exception e) {
			System.err.println("Error: Target File Cannot Be Read");
		}
	}
	
	
	//
	private static void fillPointMaps(List<String> vuln) {
		
		String vulnType = vuln.get(0).toLowerCase();
		List<String> entryPointList = Arrays.asList(vuln.get(1).split(","));
		List<String> sanitFuncList = Arrays.asList(vuln.get(2).split(","));
		List<String> vulnPointList = Arrays.asList(vuln.get(3).split(","));

		
		patterns.add(new Pattern(vuln));
		slice=new Slice(vuln);
		
		switch (vulnType) {
		case "sql injection":	
			for (String eP : entryPointList) {
				if (!SqliAnalyzer.entryPointMap.containsKey(eP)){
					SqliAnalyzer.entryPointMap.put(eP, eP);

				}
			}
			
			for (String vP : vulnPointList) {
				
				sinkPointMap.put(vP, "sqli");
				
				if (SqliAnalyzer.sinkPointMap.containsKey(vP)) {
					//If new config file has new entry for the same sink, usually this wont happen
					SqliAnalyzer.sinkPointMap.get(vP).addAll(sanitFuncList);
				}else {
					SqliAnalyzer.sinkPointMap.put(vP, sanitFuncList );
				}

			}
			
			break;
		case "cross site scripting ":
			for (String eP : entryPointList) {
				if (!XssAnalyser.entryPointMap.containsKey(eP)){
					XssAnalyser.entryPointMap.put(eP, eP);

				}
			}
			
			for (String vP : vulnPointList) {
				sinkPointMap.put(vP, "xss");
				if (XssAnalyser.sinkPointMap.containsKey(vP)) {
					//If new config file has new entry for the same sink, usually this wont happen
					XssAnalyser.sinkPointMap.get(vP).addAll(sanitFuncList);
				}else {
					XssAnalyser.sinkPointMap.put(vP, sanitFuncList );
				}

			}
			
			break;

		default:
			break;
		}
		
		
		
		vuln.clear();
		
	}

}
