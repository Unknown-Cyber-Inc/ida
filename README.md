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

- Install IDApro — This should automatically include IDAPython (python API for IDA, which we rely on).

## Installations  
See the [troubleshooting](#troubleshooting) section for help with common issues.

### For Users

- Open the terminal in the unknowncyber plugin folder, above `plugins`
- Run `pip install -e .`
- Open the `.env.example` file and change `MAGIC_API_KEY` to your UnknownCyber API key, then save and exit.
- Run `cp .env.example ./plugins/idamagic/.env`
- You can install this plugin in either `<IDA/INSTALL/DIRECTORY>/plugins` or  `$HOME/.idapro/plugins` [(the advantages can be found here)](https://hex-rays.com/blog/igors-tip-of-the-week-33-idas-user-directory-idausr/):
   * `cp plugins/* <CHOICE/OF/IDA/PLUGINS/DIRECTORY>`
- Open a binary with IDA and run the plugin with **"Edit -> Plugins -> MAGIC"** or by the shortcut **"ctrl+shift+A"**.
- 
### For Developers  

IMPORTANT: Verify that all changes work both inside of and outside of the docker container.

- Run this whole command: `cd ~ && mkdir .idapro && git clone <UNKNOWNCYBER/IDA-PLUGINS/REMOTE-REPOSITORY> && cp -ar ida-plugins/. .idapro/ && rm -rf ida-plugins
`
    * This command:
      * makes `$HOME/.idapro` if not already available
      * clones this repo
      * copies contents of this repo into `$HOME/.idapro` (this particular command includes hidden files and merges the `plugins` folder if not available already)
      * removes the original repo
      * this ensures that `$HOME/.idapro` will be the root of the github folder for this repository, and that it can work in the docker container and the standalone version of IDA.
- Run `cd $HOME/.idapro`
- Plugin development with local IDA installation:
    * (OPTIONAL): [Configure a virtual environment](#venv-setup). It's a large section but it should be straightforward.
    * Run `pip install -e dev .` (in your virtual environment if applicable).
    * Run `cp .env.example ./plugins/idamagic/.env`
    * Open and edit `./plugins/idamagic/.env` to set your API key and modify your [desired environment variables](#environment-variables)
    * Open a binary with IDA and run the plugin with **"Edit -> Plugins -> MAGIC"** or by the shortcut **"ctrl+shift+A"**.
- Plugin development inside UnknownCyber's docker container
    * Add the following to your `~/.bashrc`:
      * `export IDA_PLUGIN_PATH=$HOME/.idapro`
    * Speak with Lee to set up the docker system
    * Speak with Lee about setting the plugin's environment variables within the container
    * IMPORTANT: the `./plugins/idamagic/.env` takes precedence over the container's environment variables, as it currently is reset in the code
    * Open a binary with IDA and run the plugin with **"Edit -> Plugins -> MAGIC"** or by the shortcut **"ctrl+shift+A"**.
- Developers should read about the plugin's files which can be found [here](#files-section) as well as the notes section which can be found [here](#notes-section).

### Troubleshooting <a name="troubleshooting"></a>  

Python-related issues  

* You may need to replace commands `pip` with `pip3`, `python` with `python3`, or some variant of these dependent on your python install.
* IDA can potentially be pointing to a different version of python. ensure IDA's version of python is where you installed the package:
  * Open IDA.
  * ensure that IDA is using your desired python version (the "output" window at the bottom should display version information).
  * In this window, there is a section for commands.
  * Make sure the button on the left says "Python". It might say "IDC" or something else. If so, just click it and select "Python".
  * Enter `import cythereal_magic`
  * If there is an error, you can either:
    * reinstall python dependencies on this version (RECOMMENDED)
    * or change your python version (next step)
* Changing the version of Python that IDA points to:
  * Navigate to your IDA install folder in the terminal. `/opt/ida` for example.
  * Run `sudo ./idapyswitch`
  * If your desired version does not show up, the only way to get this to work is to find your desired python version's shared library files and run `sudo ./idapyswitch --force-path /PATH/TO/SHARED/LIBRARY/FILE`. If you don't know how to do this, it is recommended to move on to the next step 
* If there are still python-related issues there may be a need to [configure a python3.7 virtual environment](#venv-setup). It's a large section but it should be straightforward.

---

## Setup Files 
Files specifically related to setup/development/installation. All except the `README.md` are located in the `MAGIC` directory.  

### `setup.cfg`  
Contains package requirement information for plugin, plus dev requirements.  
Base python requirements for plugin:
- python-dotenv, package which will load variables from files into environment
- cythereal_magic, unknowncyber's python library which handles API requests

### `.env.example` <a name="environment-variables"></a>  
Environment variables sourced in the plugin by the python-dotenv python library. You're supposed to copy the contents to a file called `.env` for the variables to be sourced.  

#### MAGIC related environment variables  

- MAGIC_API_HOST — str, main endpoint for sending requests to MAGIC
- MAGIC_API_KEY — str, API key for connecting with MAGIC's API
#### DEV/DEBUG vars  

- HOT_RELOAD — bool, "True" allows the plugin to be tweaked for easier time with development. For example, in the plugin code this tells IDA to unload the plugin from memory as soon as it is finished running. This means we don't have to continually restart IDA to test plugin changes. This also tells the plugin to close and reload the actual forms on hotkey press.
- IDA_LOGLEVEL — bool, "True" lets the plugin print stack traces on errors and some extra information. This can take the values of "", DEBUG, INFO, WARNING, or ERROR. Users would prefer "", while developers should use DEBUG. Uses python's `logging` library.

### `README.md`  
Setup instructions and plugin notes

### `.gitignore`  
Ignores the files in the $HOME/.idapro/ irrelevant to the plugin.

### `bitbucket-pipelines.yml`  
yml pipeline file for automatic fail testing when pushing to bitbucket.

### `Justfile`  
`just` commands for atuomated tasks.

### `pyproject.toml`  
Build tools.

### `docker`  
Files related to docker plugin container setup.

## Plugin Files <a name="files-section"></a>  
Files related to the functionality of the IDA plugin. All except the `MAGIC_plugin_entry.py` are located in the `MAGIC` directory.  

### `MAGIC_plugin_entry.py`  
Contains code which is required by IDA that returns a required IDA class representing the plugin. It must be in IDA's `plugins` folder, it must contain a PLUGIN_ENTRY function, and it must return an `ida_idaapi.plugin_t` object.  
### idamagic
Base of all plugin code. Its init file handles the plugin class. This tells IDA how to initialize, run, and terminate the plugin. It also tells IDA how to load and handle the plugin in memory. The run() function is where the form creation happens.  
There are some confusing IDA-specific functionalities which I found sparse information about online. I try to explain these [here](#idamagic-notes).
* `helpers.py`  
Separate helper functions which do not particularly organize somewehere else.
* `MAGIC_hooks.py`  
Contains global hooks required by this plugin. Contains hooks for other functions. Be careful to avoid circular dependencies by only importing the required classes in its hook definition. Alternatively, these items can be moved to their own files.
* IDA_interface  
Contains code for the plugin form which is meant to act as an interface between the average IDA user's workflow and unknowncyber's procedure information.
  * Init handles the form object and most of the basic form elements
  * `_procTree.py` handles the methods related to populating the `proc_tree` element. This is a hierarchical tree that displays all of the procedures related to the currently open input file.
* unknowncyber_interface  
Contains the code for the plugin form which is just planned to be a minimal version of unknowncyber (for displaying and navigating information related to all files, etc.)
  * Init handles the form object and most of the basic form elements
  * `_filesTable.py` handles the methods related to populating the `filestable` element. This is a table that displays all of the user's files.

---

### Notes for idamagic's IDA-specifics <a name="idamagic-notes"></a>  
* `__init__.py`
  *  The plugin requires certain class members such as `wanted_name` and `wanted_hotkey`. It also requires `flags` which describe how the plugin behaves in memory. I'm honestly unsure the specifics of how these work still. `PLUGIN_FIX` tells it to remain in memory once initialized, `PLUGIN_UNL` tells it not to remain until called explicitly. the `init()` function also is required to return similar flags. `PLUGIN_SKIP` tells IDA to ignore this function, `PLUGIN_KEEP` tells IDA to keep this plugin in memory, and `PLUGIN_OK` which allows the plugin to be unloaded.
  *  `ida.require()` is a function that will explicitly reload modules. This helps for development because python modules won't reload if they are already left in memory.
* IDA_interface and unknowncyber_interface
  * Inside the class initializations of the forms, I call the `Show()` function. This function takes the created widgets and actually puts them on the GUI. This way, when the object is created it automatically shows. This is to wrap the function within the class with default options. I'm unsure exactly how these options work, as they don't appear to use these options unless the "desktop" is reset (this is a feature of IDA).
  * `OnCreate()` and `OnClose()` are functions required by `ida_kernwin.PluginForm`. These are called automatically by IDA, so if you use them keep in mind the order that they are called as this may cause errors.

---

## Developer Notes <a name="notes-section"></a>  
- Don't use IDA libraries not preceded by `ida_*`. Libraries such as `idaapi` are massive libraries, all of their functions have been split up among the `ida_*` files such as `ida_kernwin` and `ida_idaapi`.
- Search functionality is not good on the IDA SDKs. Start with the [idapy docs](https://www.hex-rays.com/products/ida/support/idapython_docs/). Try to keep the search as simple as possible. If the information is too sparse, try the [C documents](https://www.hex-rays.com/products/ida/support/sdkdoc/). The search function here is not great, try to comb the docs to see if you can find the functionality you need. Next, try reading the actual idapython libraries in your IDA install folders.

---

## Future Plans  
- Plugins should eventually use pagination when getting information from the unknowncyber API
- Plugin should eventually convert form items like qstandarditem to PyQt's abstract versions. This requires implementation of a lot of features but allows more flexibility in terms of the data shown versus the data stored. The inspiration for my suggestion on this can be found [here](https://doc.qt.io/qt-6/model-view-programming.html).
- Can save retrieved unknowncyber information onto disk, either for later uses or just as a temporary cache.

---

## Virtual Environment Setup <a name="venv-setup"></a>  

There are four main steps in this whole section:
- [Pyenv](#pyenv)
- [idapythonrc.py](#idapython)
- [activate_this.py](#activate_this)
- [idapyswitch](#idapyswitch)

### Pyenv <a name="pyenv"></a>    

I could not get this to work with python3's venv/virtualenv, however I did get this to work with pyenv. You can find [install instructions here](https://realpython.com/intro-to-pyenv/).  
  
IMPORTANT: Make sure you install your virtual environment with shared libraries enabled. you CANNOT get IDA to work with a virtual environment without it. This is done in the pyenv instructions above by replacing `pyenv install <OPTIONS> <VERSION>` with `env PYTHON_CONFIGURE_OPTS="--enable-shared" pyenv install <OPTIONS> <VERSION>`.  

After installing pyenv and the version you want:
- Run `pyenv virtualenv <VERSION> <VENV_NAME>`
- Run `pyenv activate <VENV_NAME>`
- Reinstall python packages to this environment using `pip install -e .` in the plugins directory
- Run `pyenv deactivate`

### idapythonrc.py <a name="idapython"></a>  

- Note your virtual environment's path as `path/to/venv` above the `bin` folder. If following the previous instructions, it should be `$HOME/.pyenv/versions/<VERSION>`.
- In `IDAINSTALLFOLDER/python/examples/core` there is a script `idapythonrc.py`
    * Run `cp idapythonrc.py ~/.idapro`
        * Placing it here means IDA will run this code directly after initialization
    * Append the code in the following block to `~/.idapro/idapythonrc.py`
        * This will execute a script activating the virtual environment that IDA will use
        * `path/to/venv` refers to your virtual environment path above its `bin` directory
        
        contents to add to `idapythonrc.py`:  
        
        <p></p>
        
        ```python
        import os
        import ida_diskio
        virtualenv_path = "path/to/venv"

        def activate_virtualenv(virtualenv_path):
        for bindir in ("Scripts", "bin"):
            activate_this_path = os.path.join(virtualenv_path, bindir, "activate_this.py")
            if os.path.exists(activate_this_path):
                break
        else:
            raise ValueError('Could not find "activate_this.py" in ' + virtualenv_path)

        with open(activate_this_path) as f:
            exec(f.read(), dict(__file__=activate_this_path))

        activate_virtualenv(os.path.join(ida_diskio.get_user_idadir(), virtualenv_path))
        ```  
        
        <p></p>
        
### activate_this.py <a name="activate-this"></a>

- The above code requires a script in the virtual environment bin that is deprecated in later versions of python virtual environment tools.
    * Create a file in `path/to/venv/bin` called `activate_this.py`. Note this goes in the `bin` folder.
    * Appending the code in the following block essentially tells the running application (IDA in this case) to prepend the virtual environment to its PATH, thereby prioritizing that python environment.
        * NOTE: the line `site_packages = os.path.join(base, 'lib', 'python%s' % sys.version[:3], 'site-packages')` may fail in certain python versions since it is looking for only the third character in, say, `3.7.9`
        
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

### idapyswitch <a name="idapyswitch"></a>  

- Note your python environment's shared library folder. If following the previous instructions, it should be `$HOME/.pyenv/versions/<VERSION>/lib`.
- Navigate to your IDA install folder.
- Run `sudo ./idapyswitch --force-path path/to/shared/libraries/<VERSION>m.so`  
- IDA should now run in the virtual environment. Check the IDA output window to check that the correct version is loaded.