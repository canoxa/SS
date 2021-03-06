package pt.ulisboa.tecnico.ssoft.analizer;

import java.util.ArrayList;
import java.util.List;

public class Slice {

	public List<String> lines;
	public Pattern pattern;
	public String safevar = "";
	public String query = "";
	public boolean vulnerability=false;
	public List<String> varinsidequery=new ArrayList<String>();
	private String sink = "";
	private String entryPoint = "";
	private String sanitize = "";

	
	public Slice(List<String> x)
	{
		//load all lines from input file
		lines=x;
	}
	
	//-------> XSS

	public boolean isWhatType(Pattern patt)
	{
		pattern=patt;
		boolean istest=false;
		for(String l:lines)
		{
		for(String x:pattern.vulnPointList)
		{
			if(l.contains(x))
				istest=true;
		}
		}
		return istest;
	}
	
	
	public boolean isVulnurableSQLI(Pattern patt)
	{
		vulnerability=false;
		//load 1 of our Patterns in configuration file
		pattern=patt;
		//start calculate if program is vulnerable
		findSink();
		//return if is our code vulnerable
		return vulnerability;
	}	
	
	public void findSink()
	{
		//find sink line
		for (String l : lines)
		{
	        System.out.println("l: "+l);
	        
		for (String e : pattern.vulnPointList) {
	        System.out.println("e: "+e);

			if(l.contains(e))
			{
				String valueofvar=l;
				//command doesn't have to be saved into variable
				if(l.contains("="))
					valueofvar =l.split("=")[1];
				
				// get variables in Sink
				String valuesinside =valueofvar.split("\\(")[1].split("\\)")[0];
				String[] values= valuesinside.split(",");
				for(String x : values)
				{
		        findQuery(x);
				}
			}
		}
		}
	}
	
	public String returnValueOfVariable(String value)
	{
		String x="";
		for (String l : lines) {
			if(l.contains(value+"=") || l.contains(value+" ="))
				 x =l.split("=",2)[1];	
		}
		return x;
	}
	
	public void findQuery(String value)
	{
		String var=returnValueOfVariable(value);
		Boolean test=false;
		String sanit=var.split("\\(")[0];
		
		for(String x : pattern.sanitFuncList)
		{
			if(sanit.contains(x))
			test=true;
		}
		
		//if query contains Sanit function, this part of code is not vulnerable
		if(test==true)
		{
	        System.out.println("System is NOT vulnerable");
		}else
		{
			List<String> variablesinquery= new ArrayList<String>();

			//finding variables in Query
			String[] array= var.split("'");
			for(String x : array)
			{
	        if(x.contains("$"))
	        		{
	        			variablesinquery.add(x);
	        	        System.out.println("Variable in Query: "+x);
	        		}
			}
			//check if variables in query are entry points. If YES, this part of code is vulnerable
			for(String x: variablesinquery)
			{
				if(isVariableEntryPoint(x))
				{
					vulnerability=true;
				}
			}
		}
		
	}
	
	public boolean isVariableEntryPoint(String x)
	{
		boolean isentrypoint=false;
		String var=returnValueOfVariable(x);
		
		for (String e : pattern.entryPointList) {
			if(var.contains(e))
			{
				isentrypoint=true;
			}
		}
		return isentrypoint;
	}
	
	
	
	//-------> XSS

	public String separateString(String line,String lastword)
	{
		String value= line.split(lastword)[1];
		
		String value2=value.split(">|\\;")[0];
		return value;
	}
	public boolean isVulnurableXSS(Pattern patt)
	{
		vulnerability=false;
		safevar="";
		query="";
		varinsidequery=new ArrayList<String>();
		//load 1 of our Patterns in configuration file
		pattern=patt;
		//start calculate if program is vulnerable
		findSink2();
		//return if is our code vulnerable
		return vulnerability;
	}	
	
	public void findSink2()
	{
		//find sink line
		for (String l : lines)
		{
	        
		for (String e : pattern.vulnPointList) {
			if(l.contains(e))
			{
				
				String x =separateString(l,e);
				boolean isentrypoint=false;				
				for (String z : pattern.entryPointList) 
					if(x.contains(z))
						isentrypoint=true;
				
				//x == entrance alebo premenna? ak premenna, tak skontroluj vuln
				if(isentrypoint)
				{
					vulnerability=true;
				}
				else
				{
					String[] array= x.split(" '|\\;|\\>");
//kam s tym? kam to prilepit
        			List<String> variablesinquery= new ArrayList<String>();

					for(String f : array)
					{
			        if(f.contains("$"))
			        		{
			        			String par=f.replaceAll("\\s","");
			        			variablesinquery.add(par);
			        		}
					}
					boolean isentrypoint2=false;				
					for(String o: variablesinquery)
					{
						String valueofvariable=returnValueOfVariable(o);
						boolean testsanit=false;
						for (String p : pattern.sanitFuncList) 
							if(valueofvariable.contains(p+"("))
								testsanit=true;
							
						if(testsanit==false)
						{
							for (String w : pattern.entryPointList) 
							{
								if(valueofvariable.contains(w))
									isentrypoint2=true;
							}
							
							if(isentrypoint2)
							{
								vulnerability=true;
							}
						}
						
					}
				}

			}
		}
		}
	}

	//-------> Generic 
	
	public void isVulnerable(Pattern x) {
		pattern = x;
		findSink3();
		
	}

	private void findSink3() {
		//look for the sink in all lines
		for (String l : lines)
		{ 
			for (String e : pattern.vulnPointList) 
			{	// If found sink look if in the same line finds the entry point
				if(l.contains(e))
				{
					sink = e;
					String x = separateString(l, e);
					
					for (String z : pattern.entryPointList) 
					{
						if(x.contains(z))
						{
							entryPoint = z;
							output();
							return;
						}
					}
					//Entry point not found, split the string to find variables
					String[] var =  separateString2(x);
					//recursive search of sanitization func and entry points 
					recursiveFind(var);
					
							
										
				}
			}
		}
	}

	private void recursiveFind(String[] var){
		List<String> variablesinquery= new ArrayList<String>();
		//search variables in line
		for(String v : var)
		{
        if(v.contains("$"))
        		{
        			variablesinquery.add(v);
        		}
		}		
		//If no more variables found, end of recursive search (we are in the top of the file)
		if (variablesinquery.isEmpty()) {
			output();
			return;
		}
		
		String valueofvariable = "";
		for(String o: variablesinquery)
		{
			
			String aux =returnValueOfVariable(o);
			if (!aux.isEmpty()) {
				valueofvariable = aux;
			}
			for(String p : pattern.sanitFuncList)
			{	
				if(valueofvariable.contains(p))
				{
					sanitize = p;
				}																
			}
			
			for (String p1 : pattern.entryPointList) 
			{
				if(valueofvariable.contains(p1))
				{
					entryPoint = p1;
					output();
					return;
				}
			}
		}
		// split String to find variables
		String[] array= separateString2(valueofvariable);
		recursiveFind(array);
		
	}
	
	private void output() {
		if (sanitize.isEmpty()) {
			System.out.println("The slice is vulnerable");
			System.out.println("Entry point: " + entryPoint);
			System.out.println("Sensitive sink: " + sink);
		}else {
			System.out.println("The slice is NOT vulnerable");
			System.out.println("Entry point: " + entryPoint);
			System.out.println("Sanitization function: " + sanitize);
			System.out.println("Sensitive sink: " + sink);
		}

	}

	private String[] separateString2( String e) {
		String value= e;
		value = value.replaceAll("[)(?']", " ");
		String[] value2 = value.replaceAll("^[,\\s]+", "").split("[,\\s]+");
		return value2;
	}
}
