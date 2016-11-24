package pt.ulisboa.tecnico.ssoft.analizer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SqliAnalyzer {
	
	public static Map<String,List<String>> sinkPointMap = new HashMap<>();
	public static Map<String, String> entryPointMap = new HashMap<>();
	
	private static List<String> lines = new ArrayList<String>();
	
	
	public static void validate(String vulnCode, String sink) {
		
		String var = "";
		String safevar = "";
		String query = "";
		
		lines = Arrays.asList(vulnCode.split(";"));

		for (String l : lines) {
			
			//name of variable for Entrance
			if (!var.equals("")) {
				for (String e : entryPointMap.keySet()) {
					if(l.contains(e)){
						var = l.split("=")[0];
					}
				}
			//name of variable for Created Query	
			}else if(!query.equals("")){
				if(l.contains(var)){
					query = l.split("=")[0];
					
			//name of safe variable	
				}}else if (!safevar.equals("") && l.contains(sink)) {
					for (String e : entryPointMap.keySet()) {
						if(l.contains(e)){
							var = l.split("=")[0];
						}
					}
			
			}else{
				if(l.contains(query) && l.contains(sink)){
					System.out.println("SQL Injection");
				}else if (l.contains(query)) {
					for (String sanFunc : sinkPointMap.get(sink)) {
						if (l.contains(sanFunc)) {
							System.out.println(sanFunc);
						}
					}
				}
			}
			

			
		}
		
	}
	

}
