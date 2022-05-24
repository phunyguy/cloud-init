.. _qemu_tutorial:

Tutorial
********

In this tutorial, we will create our first cloud-init user data config
and deploy it into a qemu vm. We'll be using Qemu_ for this tutorial
which is commonly used on Linux for running virtual machines. Several
popular virtual machine tools, including Libvirt, LXD, Vagrant, etc.

Install Qemu
------------

.. code-block:: shell-session

    $ sudo apt install qemu-system-x86

If your Linux distribution does not use apt for package management, or
if this does not work for you, see the `download page`_ for
instructions.

Download a Cloud Image
----------------------

.. code-block:: shell-session

    $ wget https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img

Cloud images have cloud-init installed and will configure the system on boot.


Define our user data
====================

Create the following file on your local filesystem at ``/tmp/my-user-data``:

.. code-block:: yaml

   #cloud-config
   password: Password
   chpasswd:
     expire: False


Here we are defining our cloud-init user data in the
:ref:`cloud-config<topics/format:Cloud Config Data>` format, using the
`runcmd`_ module to define a command to run. When applied, it
should set the password for the defaul user to "password".

Launch a vm with our user data
=====================================

Now that we have LXD setup and our user data defined, we can launch an
instance with our user data:

.. code-block:: shell-session

    $ qemu-system-x86_64 \
        -net nic         \
        -net user        \
        -machine accel=kvm,type=q35 \
        -cpu host        \
        -m 512           \
        -nographic       \
        -hda jammy-server-cloudimg-amd64.img \
        -smbios type=1,serial=ds=nocloud-net;s=file://tmp/my-user-data

Verify that cloud-init ran successfully
=======================================

After launching the virtual machine, we should be able to connect
to our instance using the default user:password (ubuntu:Password)

.. code-block:: shell-session

    $ lxc shell my-test

You should now be in a shell inside the LXD instance.
Before validating the user data, let's wait for cloud-init to complete
successfully:

.. code-block:: shell-session

    $ cloud-init status --wait
    .....
    cloud-init status: done
    $

We can now verify that cloud-init received the expected user data:

.. code-block:: shell-session

    $ cloud-init query userdata
    #cloud-config
    runcmd:
      - echo 'Hello, World!' > /var/tmp/hello-world.txt

We can also assert the user data we provided is a valid cloud-config:

.. code-block:: shell-session

    $ cloud-init schema --system --annotate
    Valid cloud-config: system userdata
    $

Finally, verify that our user data was applied successfully:

.. code-block:: shell-session

    $ cat /var/tmp/hello-world.txt
    Hello, World!
    $

We can see that cloud-init has consumed our user data successfully!

Tear down
=========

Exit the qemu shell using ``ctrl-a x`` (that's ctrl and a
simultaniously, followed by ``x``).


What's next?
============

In this tutorial, we used the runcmd_ module to execute a shell command.
The full list of modules available can be found in
:ref:`modules documentation<modules>`.
Each module contains examples of how to use it.

You can also head over to the :ref:`examples<yaml_examples>` page for
examples of more common use cases.

.. _Qemu: https://www.qemu.org
.. _other installation options: https://linuxcontainers.org/lxd/getting-started-cli/#other-installation-options
.. _runcmd: https://cloudinit.readthedocs.io/en/latest/topics/modules.html#runcmd
