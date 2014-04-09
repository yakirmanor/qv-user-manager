About
=====

this is a fork from braathen code at: <https://github.com/braathen/qv-user-manager/>

this fork is to help adjust braathen code to QV11 and Visual studio 2012 and 2013

you may want to check this link before you start 'Qlikview Server CAL Manager':

<http://community.qlik.com/docs/DOC-5281>

and you should start with reading the 'QlikView Server Reference Manual 11'

<http://d1cf4w4kkla6tb.cloudfront.net/qlikview/11.00/11414/QlikView%20Server%20Reference%20Manual_ENG.pdf>

first step
-----------

	download the code from braathen git
	(you can download this code with all the updates but what's the fun in that...
	plus braathen may update his code)

second step
-----------

	open the solution explorer in Visual Studio
	right click on 'QMSBackendService' and select 'Configure Service Reference...'
	add the /Service to the link like so:
	http://localhost:4799/QMS/Service 
	(if your running VS on the same machine)

third step
-----------

	again open the solution explorer
	right click on 'QMSBackendService' and select 'Update Service Reference'
	now build the project
	and... oh no! so many bugs!!!

forth step
-----------
	
	a. replace 'QMSBackendClient' with the entire project in 'QMSClient'
	b. replace all unrecognised 'Exception' with 'System.Exception' (only the unrecognised ones)
	c. comment the lines: 244-252, 266 (VS -> TOOLS -> Options... -> Text Editor -> All Languages -> General -> Line numbers)
	   its basically all the lines under: 'Check if PreloadMode is Restricted, if so get the dates'
	   and the Console.WriteLine with 'preloadMode, loadedDays, between' (or just edit the line)
	d. build and run the project!
	e. didn't work? 'Service key is missing', go to fifth step.
	f. if you want a nicer solution for dosc see 'http://community.qlik.com/docs/DOC-3649'
	
fifth step
-----------

	go to the app.config to line 45 (the <client> node)
	replace the code that was auto generated by the update of the service:
	        <client>
	            <endpoint address="http://localhost:4799/QMS/Service" behaviorConfiguration="ServiceKeyEndpointBehavior"
	                binding="basicHttpBinding" bindingConfiguration="BasicHttpBinding_IQMSBackend"
	                contract="QMSBackendService.IQMSBackend" name="BasicHttpBinding_IQMSBackend" />
	            <endpoint address="http://win-jsvlpr19hbb:4799/QMS/Service" binding="basicHttpBinding"
	                bindingConfiguration="BasicHttpBinding_IQMS" contract="QMSBackendService.IQMS"
	                name="BasicHttpBinding_IQMS" />
	            <endpoint address="http://win-jsvlpr19hbb:4799/ANY/Service" binding="basicHttpBinding"
	                bindingConfiguration="BasicHttpBinding_IQTService" contract="QMSBackendService.IQTService"
	                name="BasicHttpBinding_IQTService" />
	        </client>
	
	with:
	    <client>
      		<endpoint address="http://localhost:4799/QMS/Service" binding="basicHttpBinding"
          	bindingConfiguration="BasicHttpBinding_IQMS" contract="QMSBackendService.IQMS"
          	name="BasicHttpBinding_IQMS" behaviorConfiguration="ServiceKeyEndpointBehavior" />
    	    </client>

and Wallah! Enjoy!
------------------
![Screenshot of example application](https://raw.github.com/yakirmanor/qv-user-manager/master/images/screenshot2.png)

Wait
----

now you want to change some stuff, and you may want some documentation
you can fing it in this git (under '\extras') or download it from:

<http://community.qlik.com/docs/DOC-2683>

you need to unblock it to read it like so:
![Screenshot of example application](https://raw.github.com/yakirmanor/qv-user-manager/master/images/unblock.PNG)


