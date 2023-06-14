# IDA Plugin

Plugin for interfacing Cythereal MAGIC with IDA — Interactive Disassembler

After performing the installation instructions, the plugin should load automatically in IDA. Access it through the menus at the top **"Edit -> Plugins -> MAGIC"** or by the shortcut **"ctrl+shift+A"**.

## Features
- Widget which gathers procedure information from UnknownCyber on the user's currently opened file
- Displays important and relevant information for reverse engineering purposes such as:
    * strings
    * api calls
    * if the procedure is tagged as a library procedure
    * if the procedure is tagged as a clone, variant, or related
    * ocurrences of the procedure in the UnknownCyber database
    * notes associated with the procedure, procedure group, and all files containing this procedure
    * tags associated with the procedure, procedure group, and all files containing this procedure
    * list of files which contain similar procedures
- Doubleclicking a procedure in the widget jumps IDA to the effective address associated with the procedure
- Scrolling through IDA will open the associated procedures automatically in the widget
- Minimal version of UnkownCyber site within IDA

## Built and Verified for
This does not mean it won't work for other versions, but there are no guarantees yet. This should be able to work with Windows installations as long as it's kept in mind that this guide is currently written for Linux.

- IDA Pro 8.2.230124 (64-bit) GUI version
- IDAPython 64-bit v7.4.0
- Python 3.7.16
- Ubuntu 22.04.2 LTS

## Prerequisites

- DEVELOPERS: it is recommended to use a python virtual environment and install requirements on that instead. [Setting this up with IDA requires some configuration](#development-setup).
- Install IDApro — This should automatically include IDAPython (python API for IDA, which we rely on).
- Install python requirements. (Developers, do this in your virtual environment if you chose to use one). <a name="python-requirements"></a>
    * Open terminal and navigate to the MAGIC folder
    * Run `pip install -r requirements.txt`
    * If this doesn't work, replace `pip` with `pip3`
    * IDA can potentially point to multiple versions of python. Make sure IDA's version has these packages installed.

## Installation
- Move the `MAGIC` directory and `MAGIC_plugin_entry.py` to your IDA plugin directory. In my case `/opt/ida/plugins`. These can also be installed to `$HOME/.idapro/plugins` [as per this link](https://hex-rays.com/blog/igors-tip-of-the-week-33-idas-user-directory-idausr/)
- Copy the contents of `.env.example` to a file called `.env`
    * If you are not a developer, you should only need to change `MAGIC_API_KEY` to your MAGIC API key
    * If are a developer, read the [environment variables](#environment-variables) section and change them accordingly
- That's all. Info about the plugins files can be found [here](#files-section). Open a binary with IDA and run the plugin with **"Edit -> Plugins -> MAGIC"** or by the shortcut **"ctrl+shift+A"**.

---

## Development Setup <a name="development-setup"></a>
- Create a virtual environment and note its path `yourvenv/bin/`
- Run `source yourvenv/bin/activate` to launch the virtual environment
    * This is when you install the [python requirements](#python-requirements).
        * To ensure that IDA is running off of the correct environment, install a simple python library which is not included in the default python installation ["art"](https://pypi.org/project/art/) into your target environment
        * If you can import and run the above library through IDA's CLI for python, then IDA is using the correct environment
- You can type `deactivate` in the terminal to exit the virtual environment
- In `idapro/python/examples/core` there is a script `idapythonrc.py`
    * Copy the `idapythonrc.py` script inside `~/.idapro/`
        * Placing it here means IDA will run this code directly after core initialization
    * Append the code in the following block to `~/.idapro/idapythonrc.py`
        * This will execute a script activating the virtual environment that IDA will use
        * `path/to/your/virtual/environment` refers to your virtual environment path above its `bin` directory
        
        contents to add to `idapythonrc.py`:  
        
        <p></p>
        
        ```python
        import os
        virtualenv_path = "path/to/your/virtual/environment"

        def activate_virtualenv(virtualenv_path):
        for bindir in ("Scripts", "bin"):
            activate_this_path = os.path.join(virtualenv_path, bindir, "activate_this.py")
            if os.path.exists(activate_this_path):
                break
        else:
            raise ValueError('Could not find "activate_this.py" in ' + virtualenv_path)

        with open(activate_this_path) as f:
            exec(f.read(), dict(__file__=activate_this_path))

        activate_virtualenv(os.path.join(idaapi.get_user_idadir(), virtualenv_path))
        ```  
        
        <p></p>
        
- The above code requires a script in the virtual environment bin that is deprecated in later versions of `python -m venv` 
    * Create a file in `path/to/your/virtual/environment/bin` called `activate_this.py`
    * Appending the code in the following block essentially tells the running application (IDA in this case) to prepend the virtual environment to its PATH, thereby prioritizing that python environment
        * As a note, the line `site_packages = os.path.join(base, 'lib', 'python%s' % sys.version[:3], 'site-packages')` may fail in certain python versions since it is looking for only the third character in, say, `3.7.9`
        
        contents of `activate_this.py`:  
        
        <p></p>
        
        ```python
        """By using execfile(this_file, dict(__file__=this_file)) you will
        activate this virtualenv environment.
        This can be used when you must use an existing Python interpreter, not
        the virtualenv bin/python
        """
        try:
            __file__
        except NameError:
            raise AssertionError(
                "You must run this like execfile('path/to/activate_this.py', dict(__file__='path/to/activate_this.py'))")
        import sys
        import os
        old_os_path = os.environ['PATH']
        os.environ['PATH'] = os.path.dirname(os.path.abspath(__file__)) + os.pathsep + old_os_path
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if sys.platform == 'win32':
            site_packages = os.path.join(base, 'Lib', 'site-packages')
        else:
            site_packages = os.path.join(base, 'lib', 'python%s' % sys.version[:3], 'site-packages')
        prev_sys_path = list(sys.path)
        import site
        site.addsitedir(site_packages)
        sys.real_prefix = sys.prefix
        sys.prefix = base
        # Move the added items to the front of the path:
        new_sys_path = []
        for item in list(sys.path):
            if item not in prev_sys_path:
                new_sys_path.append(item)
                sys.path.remove(item)
        sys.path[:0] = new_sys_path
        ```  
        
        <p></p>

---

## Setup Files <a name="files-section"></a>  
Files specifically related to setup/development/installation. All except the `README.md` are located in the `MAGIC` directory.
### `requirements.txt`  
Python requirements
- python-dotenv, package which will load variables from files into environment
- cythereal_magic, unknowncyber's python library which handles API requests

### `.env.example` <a name="environment-variables"></a>  
Environment variables sourced in the plugin by the python-dotenv python library. You're supposed to copy the contents to a file called `.env` for the variables to be sourced.
#### MAGIC related environment variables
- MAGIC_API_HOST — str, main endpoint for sending requests to MAGIC
- MAGIC_API_KEY — str, API key for connecting with MAGIC's API
#### DEV/DEBUG vars
- PLUGIN_DEVELOP — bool, "True" allows the plugin to be tweaked for easier time with development. For example, in the plugin code this tells IDA to unload the plugin from memory as soon as it is finished running. This means we don't have to continually restart IDA to test plugin changes.
- PLUGIN_DEVELOP_RECREATE_WIDGETS — bool, "True" Tells the plugin to delete and reload plugin widgets on hotkey press
- PLUGIN_DEBUG — bool, "True" lets the plugin print stack traces on errors and some extra information
- PLUGIN_DEVELOP_LOCAL_API — bool, "True" allows the plugin to redirect requests to local instance of unknowncyber
- MAGIC_API_HOST_LOCAL — str, main endpoint for sending requests to local instance of MAGIC
- MAGIC_API_KEY_LOCAL — str, API key for connecting with local instance of MAGIC's API
- PLUGIN_DEVELOP_LOCAL_CERT_PATH — str, path to dev.crt cert file. running an environment on localhost may create cert validation errors when using cythereal_magic python package. this will point those requests to the right directory.

### `README.md`  
Setup instructions and plugin notes

## Plugin Files  
Files related to the functionality of the IDA plugin. All except the `MAGIC_plugin_entry.py` are located in the `MAGIC` directory.
### `MAGIC_plugin_entry.py`  
Contains code which is required by IDA that returns a required IDA class representing the plugin.
### `MAGIC_form.py`  
Contains the code for the plugin form which is just planned to be a minimal version of unknowncyber (for displaying and navigating information related to all files, etc.)
### `MAGIC_hooks.py`  
Contains global hooks required by this plugin.
### `MAGIC_sync_scroll.py`  
Contains code for the plugin form which is meant to act as an interface between the average IDA user's workflow and unknowncyber's procedure information.