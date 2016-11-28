package pt.ulisboa.tecnico.ssoft.analizer;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;


public class Analyzer {
	

	public static List<Pattern> patterns=new ArrayList<Pattern>();
	
	public static List<Pattern> patternsSQLI=new ArrayList<Pattern>();
	public static List<Pattern> patternsXSS=new ArrayList<Pattern>();
	
	public static Map<String,List<Pattern>> patternsList = new HashMap<>();
	
	public static Slice slice;
	
	private static String vulnCode = "";
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
	
	}


	public static void analysis()
	{
		boolean isvulnerableSQLI=false;
		boolean isvulnerableXSS=false;
		String res="";
		for (Pattern p : patterns)
			if(slice.isWhatType(p))
				res=p.vulnType;

		
		//-------> Generic 
		
		for(Pattern x: patternsList.get(res)){
			slice.isVulnerable(x);	
		}
	    
		//-------> Generic 
		
		/*if(res.contains("sql injection"))
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
	        System.out.println("Vulnerability: Cross site scripting");*/

	}

	private static void readFile(String file) throws IOException {
		List<String> lines = Files.readAllLines(Paths.get(file), StandardCharsets.UTF_8);
		for (String string : lines) {
			vulnCode = vulnCode+ string;			
		}
		
		List<String> nLines = new ArrayList<String>(Arrays.asList(vulnCode.split(";")));

		slice= new Slice(nLines);
		//slice=new Slice(lines);
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
					
					//-------> Generic 
					if(patternsList.get(s.vulnType) == null){
						patternsList.put(s.vulnType, new ArrayList<Pattern>());
						patternsList.get(s.vulnType).add(s);
					}else {
						patternsList.get(s.vulnType).add(s);
					}
					//-------> Generic 
					
					//
					/*if(s.vulnType.contains("injection"))
					{
						patternsSQLI.add(s);
					}
					if(s.vulnType.contains("cross site scripting"))
					{
					patternsXSS.add(s);
					}*/
					//
					vuln.clear();
				}else{
					vuln.add(line);
				}	
				
			}
			
			Pattern p=new Pattern(vuln);
			patterns.add(p);
			
			//-------> Generic 
			if(patternsList.get(p.vulnType) == null){
				patternsList.put(p.vulnType, new ArrayList<Pattern>());
				patternsList.get(p.vulnType).add(p);
			}else {
				patternsList.get(p.vulnType).add(p);
			}
			//-------> Generic 
			
			/*if(p.vulnType.contains("injection"))
			{
				patternsSQLI.add(p);
			}
			if(p.vulnType.contains("cross site scripting"))
			{
			patternsXSS.add(p);
			}*/

			
		} catch (Exception e) {
			System.err.println("Error: Target File Cannot Be Read");
		}
	}

}
