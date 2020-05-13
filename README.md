# FIIT-BP-Canaries-Experts
## Running in Visual Studio 
Set up the environment 
Make sure you've downloaded Visual Studio Code (VSCode) on your system. If you don't have it yet, you can download it here: https://code.visualstudio.com/ 

First clone the project and navigate to the folder:

    ~$ git clone git@github.com/KarolinaTrn168/FIIT-BP-Canaries-
Experts.git 

    ~$ cd /path/file

To create a virtual environment run the following commands: 

~$ apt install python3 python3-pip
    ~$ pip3 install virtualenv
    ~$ virtualenv virtual_name

Now open VSCode and choose to open a project folder: File → Open folder → choose your folder

Open the Extensions explorer (Ctrl+Shift+x), search for Python and install it. 

Open the terminal within VSCode (Ctrl+j) and enter following commands to activate the previously created virtual environment: 

    ~$ source ./virtual_name/bin/activate
    ~$ pip3 install packages (-r requirements.txt)

Now open the command palette (Ctrl+Shift+p) and do the following steps: 
1. Search for the Configure task → create tasks.json → Other
The created tasks.json should look as follows:
    {
        "label":"Export requirements",
        "type":"shell",
        "command":"pip3",
        "args": [
            "freeze", ">", "requirements.txt"
        ]
        "problemMatcher":[ ]
}
2. Run task → Export requirement 
This will automatically save all the required packages into requirements.txt file. 

Possible problem, that can occur: You have to check the python interpreter. For this go to the command palette and search for Python: Select interpreter - this has to be python3 (virtualenv). 
In case the interpreter is not python3, then go to the VSCode terminal and run the following commands: 

~$ python3 -m virtualenv virtual_name 
~$ source ./virtual_name/bin/activate

This will ensure, that the virtual environment is created through python3. 

## Configure the server 
You may clone the Github repository (github.com/KarolinaTrn168/FIIT-BP-Canaries- Experts.git)  and create the configuration file like shown below. For this you have to install git and python to be able to set up the virtual environment.

~$ sudo apt install git python3 python3-pip

After this is finished, clone your git repository. 

~$ git clone git@ github.com/KarolinaTrn168/FIIT-BP-Canaries- Experts.git

Within the projects directory you have to install all the required packages and set up the virtual environment with the following commands: 
    
~$ cd ./FIIT-BP-Canaries-Experts
~$ pip install -r ./requirements.txt

~$ pip3 install virtualenv
~$ virtualenv virtual_name
~$ source ./virtual_name/bin/activate

The configuration file should look as follows:
{
   "redis": {
       "host_redis": "Hostname",
       "port_redis": Portnumber,
       "debug_redis": true
   },

   "canaries_api": {
       "username_api": "Username",
       "password_api": "Password",
       "url_api": "URL",
       "version_api": "Version"
   }
}

## Syslog configuration
First you have to install the required packages and create the configuration files, all of which are listed below. All these steps you have to do as root. 

~$ apt install syslog-ng
~$ cd /etc/syslog-ng/conf.d

Create config file: touch name.conf
        #This will filter the logs of the script, which come locally #to syslog. 
        #The destination defines where the logs should be stored ( #/path ).
        destination d_canary_experts { file('/var/log/canary- experts.log'); };

        #set the filter with the logging name (canary-experts), to #filter it through the regex filter
        filter f_canary_experts { program("canary\-experts"); };

        #log from system logs (in my case s_src), filter the python #script and write to the destination file
        log { source(s_src); filter(f_canary_experts); destination(d_canary_experts); };

Create config file: touch name2.conf
        #tells syslog to listen on port 12345 on the localhost, in #case something gets there, it will be logged into the #destination file 
        source remote_canary_expert_host {
           tcp(ip(127.0.0.1) port(12345));
           udp(ip(127.0.0.1) port(12345));
           udp(default-facility(syslog) default-priority(emerg));
           tcp(default-facility(syslog) default-priority(emerg));
        };
        destination d_canary_expert_remote {file('/var/log/canary- expert-remote.log'); };
        log { source(remote_canary_expert_host); destination(d_canary_expert_remote); };

After this you have to restart and enable syslog: 

~$ systemctl restart syslog-ng
~$ systemctl enable syslog-ng

Possible problem, that can occur: Getting the following warnings: 
perl: warning: Falling back to a fallback locale ("en_US.UTF-8").
perl: warning: Setting locale failed.

Therefore you have to check locales -a and run the following commands: 
~$ locale-gen en_US.UTF-8
~$ export LANGUAGE=en_US.UTF-8
~$ export LANG=en_US.UTF-8
~$ export LC_ALL=en_US.UTF-8

## Supervisor configuration
Supervisor is a client/server system that allows its users to manage a number of processes (especially long-running programs) by providing a consistent interface through which they can be monitored and controlled. 
First you have to install  and start the supervisor on your system (as root):
    
    ~$ apt-get install supervisor 
    ~$ service supervisor restart

After the supervisor is successfully installed and started you have to create the configuration file within the conf.d directory:
    
    ~$ cd /etc/supervisor/conf.d

Create config file: touch name.conf
        #define the program, it's name, process name and the full path to the program 
        [program:program_name]
        process_name=proces_name
        command=/path/to/the/program
        autostart=true
        autorestart=true
        numprocs=1
        startretries=10
        startsecs=7
        redirect_stderr=true
        stopasgroup=true

Note: If you want to add more or different functionality: http://supervisord.org/configuration.html#program-x-section-settings

After you have created the configuration file, you need to update the supervisor. These two commands you have to do every time you change something in the configuration file: 

    ~$ supervisorctl reread
    ~$ supervisorctl update





