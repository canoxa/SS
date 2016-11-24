package pt.ulisboa.tecnico.ssoft.analizer;

import java.util.Arrays;
import java.util.List;

public class Pattern {

	public String vulnType;
	public List<String> entryPointList;
	public List<String> sanitFuncList;
	public List<String> vulnPointList;

	
	public Pattern(List<String> vuln)
	{
		vulnType = vuln.get(0).toLowerCase();
		entryPointList = Arrays.asList(vuln.get(1).split(","));
		sanitFuncList = Arrays.asList(vuln.get(2).split(","));
		vulnPointList = Arrays.asList(vuln.get(3).split(","));
	}
}
