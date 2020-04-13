/*
 * Copyright (c) 2010, Sebastian Sdorra
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of SCM-Manager; nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * http://bitbucket.org/sdorra/scm-manager
 *
 */
registerGeneralConfigPanel({
    xtype: 'configForm',
    title: 'OpenID Authentication',
    items: [{
            xtype: 'checkbox',
            inputValue: 'true',
            fieldLabel: 'Enabled',
            name: 'enabled',
            helpText: 'Enable or disable the plugin. This will override the default login process. You will need to provide at least one admin email.'
        },
        {
            xtype: 'textfield',
            fieldLabel: 'Provider URL',
            name: 'provider-url',
            helpText: 'The URL from the provider that contains the endpoints for authentication (.well-known).',
            allowBlank: false
        },
        {
            xtype: 'textfield',
            fieldLabel: 'Client ID',
            name: 'client-id',
            helpText: 'The client id from the provider.',
            allowBlank: false
        },
        {
            xtype: 'textfield',
            fieldLabel: 'Client Secret',
            name: 'client-secret',
            helpText: 'The client secret used from the provider to identify and authorize the client.',
            allowBlank: false
        },
        {
            xtype: 'textfield',
            fieldLabel: 'User Identifier',
            name: 'user-identifier',
            helpText: 'Which user information from the provider is going to be used as a unique identifier by SCM. It can be "Username", "Email" or "SubjectID (Default)".',
            allowBlank: false
        },
        {
            xtype: 'textfield',
            fieldLabel: 'Admin Role Name',
            name: 'admin-role',
            helpText: 'Which client role from the provider user account is going to determine if a user must have admin access to SCM. <b>[IMPORTANT]</b> It will override the scm admin setting.',
            allowBlank: false
        }
    ],

    onSubmit: function(values) {
        this.el.mask('Submit ...');
        Ext.Ajax.request({
            url: restUrl + 'config/auth/oidc.json',
            method: 'POST',
            jsonData: values,
            scope: this,
            disableCaching: true,
            success: function(response) {
                this.el.unmask();
            },
            failure: function() {
                Ext.MessageBox.show({
                  title : 'Error',
                  msg : 'The information you provided is not correct. Please check your inputs and try again.',
                  buttons : Ext.MessageBox.OK,
                  icon : Ext.MessageBox.ERROR
                });
                this.el.unmask();
            }
        });
    },

    onLoad: function(el) {
        var tid = setTimeout(function() {
            el.mask('Loading ...');
        }, 100);
        Ext.Ajax.request({
            url: restUrl + 'config/auth/oidc.json',
            method: 'GET',
            scope: this,
            disableCaching: true,
            success: function(response) {
                var obj = Ext.decode(response.responseText);
                this.load(obj);
                clearTimeout(tid);
                el.unmask();
            },
            failure: function() {
                el.unmask();
                clearTimeout(tid);
                alert('failure');
            }
        });
    }
});

Ext.override(Sonia.scm.Main, {

  logout : function() {
	var el = Ext.getBody();
	var tid = setTimeout(function() {
      el.mask('Logging out...',"x-mask-loading");
	}, 1000);
	Ext.Ajax.request({
      url : restUrl + 'oidc/logout',
      method : 'GET',
      scope : this,
      disableCaching : true,
      success : function(response) {
        var logoutUrl = response.responseText;
        console.log(logoutUrl);
        if (logoutUrl !== null) {
          window.location = logoutUrl;
        } else {
          location.reload();
        }
        clearTimeout(tid);
        el.unmask();
      },
      failure : function() {
        clearTimeout(tid);
        el.unmask();
        Ext.MessageBox.show({
          title : 'Error',
          msg : 'Could not reload page',
          buttons : Ext.MessageBox.OK,
          icon : Ext.MessageBox.ERROR
        });
      }
    });
  }
});