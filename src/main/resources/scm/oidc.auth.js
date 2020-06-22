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

var userIdentifiers = [
	['SubjectId'],
	['Username'],
	['Email']
];

var userIdentifiersStore = new Ext.data.ArrayStore({
	id: 0,
	fields: ['val'],
	data: userIdentifiers
});

var authenticationFlows = [
	['Resource Owner Grant Flow'],
	['Client Identification Token Flow']
];

var authenticationFlowStore = new Ext.data.ArrayStore({
	id: 1,
	fields: ['val'],
	data: authenticationFlows
});

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
            xtype: 'combo',
            fieldLabel: 'User Identifier',
            name: 'user-identifier',
            mode: 'local',
            store: userIdentifiersStore,
            displayField: 'val',
            valueField: 'val',
            forceSelection: true,
            triggerAction: 'all',
            helpText: 'Which user information from the provider is going to be used as a unique identifier by SCM. It can be "Username", "Email" or "SubjectId (Default)".'
        },
        {
            xtype: 'textfield',
            fieldLabel: 'Admin Role Name',
            name: 'admin-role',
            helpText: 'Which client role from the provider user account is going to determine if a user must have admin access to SCM Manager. <b>[IMPORTANT]</b> It will override the local admin setting.',
            allowBlank: false
        },
        {
			xtype: 'combo',
			fieldLabel: 'Client Authentication Flow',
			name: 'authentication-flow',
			mode: 'local',
			store: authenticationFlowStore,
			displayField: 'val',
			valueField: 'val',
			forceSelection: true,
			triggerAction: 'all',
			helpText: 'Choose the way external clients (Git CLI etc.) should connect with SCM Manager. <b>[IMPORTANT]</b> The identification token flow will require your provider users to have offline_access role mapped.'
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
                location.reload();
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

Ext.ns('cite');
Ext.ns('cite.oidc');

cite.oidc.pluginSettings = {};
cite.oidc.loadPluginSettings = function() {
	Ext.Ajax.request({
		url: restUrl + 'config/auth/oidc.json',
		method: 'GET',
		scope: this,
		disableCaching: true,
		success: function(response) {
			var obj = Ext.decode(response.responseText);
			cite.oidc.pluginSettings = obj;
		},
		failure: function() {
			console.log("OpenId Connect plugin configuration could not get loaded...")
		}
	});
};

loginCallbacks.push(function() {
	cite.oidc.loadPluginSettings();

	var navPanel = Ext.getCmp('navigationPanel');

	var profile_link = {
		label : 'Profile Information',
		fn : function() {
            Ext.Ajax.request({
                url: restUrl + 'oidc/profile/info.json',
                method: 'GET',
                scope: this,
                disableCaching: true,
                success: function(response) {
                    var info = JSON.parse(response.responseText);
                    cite.oidc.loadPluginSettings();
                    setTimeout(function() {
						var message = '<b>Id (username):</b> ' + info.username + '<br><b>Display Name:</b> ' + info.displayName + '<br><b>Email</b>: ' + info.email;
						if (cite.oidc.pluginSettings["authentication-flow"] === "Client Identification Token Flow") {
							message = message + '<br><br>You will have to use your username as seen above<br>and one of your issued tokens as a password to connect<br>with SCM Manager from an external client such as git CLI.';
						} else {
							message = message + '<br><br>You will have to use your provider account credentials<br>to connect with SCM Manager from an external client such as git CLI.';
						}
						Ext.Msg.alert('Profile Information', message);
                    }, 250);
                },
                failure: function() {
                    Ext.MessageBox.show({
                        title : 'Error',
                        msg : 'Could not fetch current configuration.',
                        buttons : Ext.MessageBox.OK,
                        icon : Ext.MessageBox.ERROR
                    });
                }
            });
		},
		scope : this
	};
	var tokens_link = {
		label : 'Client Identification Tokens',
		fn : cite.oidc.addTokensPanel,
		scope : this
	};

	var count = navPanel.count() - 1;

	setTimeout(function() {
		if (cite.oidc.pluginSettings["enabled"]) {
			if (cite.oidc.pluginSettings["authentication-flow"] === "Client Identification Token Flow") {
    			navPanel.insertSection(count, {
            		id: 'oidcSection',
            		title: 'OpenId Connect',
            		links: [profile_link, tokens_link]
            	});
    		} else {
    			navPanel.insertSection(count, {
            		id: 'oidcSection',
            		title: 'OpenId Connect',
            		links: [profile_link]
            	});
    		}
		}
	}, 250);

});

cite.oidc.addTokensPanel = function() {
	main.addTabPanel('tokenPanel','tokenPanel','Client Identification Tokens');
}

cite.oidc.Grid = Ext.extend(Sonia.rest.Grid, {
	parentPanel: null,
	initComponent: function() {
		var tokenStore = new Sonia.rest.JsonStore({
			proxy: new Ext.data.HttpProxy({
				url: restUrl + 'oidc/token/list.json',
				disableCaching: false
			}),
			idProperty: 'id',
			fields: ['id','body','issued-at','valid-for','expires-at'],
			sortInfo: {
				field: 'expires-at'
			}
		});

		var tokenColModel = new Ext.grid.ColumnModel({
			defaults: {
				sortable: true,
				scope: this,
				width: 200
			},
			columns: [{
				id: 'id',
				header: 'Id',
				dataIndex: 'id'
			},{
				id: 'issued-at',
				header: 'Issued At',
				dataIndex: 'issued-at',
				renderer: Ext.util.Format.formatTimestamp
			},{
				id: 'valid-for',
				header: 'Lifetime (in hours)',
				dataIndex: 'valid-for',
				renderer: function(value) {
					if (value) {
						return value;
					}
					return 'Unlimited'
				}
			},{
				id: 'expires-at',
				header: 'Expires At',
				dataIndex: 'expires-at',
				renderer: function(value) {
					if (value) {
						return Ext.util.Format.formatTimestamp(value);
					}
					return 'Never'
				}
			}]
		});

		var config = {
			autoExpandColumn: 'id',
			store: tokenStore,
			colModel: tokenColModel,
			emptyText: 'There are no active identification tokens set on your account'
		}

		Ext.apply(this, Ext.apply(this.initialConfig, config));
		cite.oidc.Grid.superclass.initComponent.apply(this, arguments);

		this.parentPanel.tokenGrid = this;
	}
});

Ext.reg('tokenGrid', cite.oidc.Grid);

cite.oidc.ConfigPanel = Ext.extend(Sonia.rest.FormPanel, {
	title: 'Default Token Configuration',
	initComponent: function() {
		var loadConfig = function(){
            Ext.Ajax.request({
                url: restUrl + 'oidc/token/config.json',
                method: 'GET',
                scope: this,
                disableCaching: true,
                success: function(response) {
                    Ext.getCmp('tokenConfig').form.setValues(JSON.parse(response.responseText));
                },
                failure: function() {
                    Ext.MessageBox.show({
                        title : 'Error',
                        msg : 'Could not fetch current configuration.',
                        buttons : Ext.MessageBox.OK,
                        icon : Ext.MessageBox.ERROR
                    });
                }
            });
		}

		var config = {
			items: [{
				id: 'lifetime',
				xtype: 'numberfield',
				fieldLabel: 'Token Lifetime',
				name: 'lifetime',
				helpText: 'The generated tokens will be valid for this amount of time (in hours). Put 0 here for unlimited lifetime.',
				allowBlank: true
            }],
			create: function(values) {
				this.el.mask('Submit ...');
				Ext.Ajax.request({
					url: restUrl + 'oidc/token/config.json',
					method: 'POST',
					jsonData: values,
					scope: this,
					disableCaching: true,
					success: function(response) {
						this.el.unmask();
						Ext.getCmp('tokenGrid').reload();
						loadConfig();
					},
					failure: function() {
						Ext.MessageBox.show({
							title : 'Error',
							msg : 'The information you provided is not correct. Please check your inputs and try again.',
							buttons : Ext.MessageBox.OK,
							icon : Ext.MessageBox.ERROR
						});
						this.el.unmask();
						loadConfig();
					}
				});
			},
			reset: function() {
				loadConfig();
			}
		}

		Ext.apply(this, Ext.apply(this.initialConfig, config));
		cite.oidc.ConfigPanel.superclass.initComponent.apply(this, arguments);
		loadConfig();
	}
});

Ext.reg('tokenConfig', cite.oidc.ConfigPanel);

cite.oidc.Panel = Ext.extend(Sonia.rest.Panel, {
	tokenGrid: null,
	initComponent: function() {
		var config = {
			tbar: [{
                xtype: 'tbbutton',
                text: this.addText,
                icon: this.addIcon,
                scope: this,
                handler: function() {
					Ext.Msg.prompt('Lifetime in hours', 'Leave this empty or override the default lifetime setting for this token:', function(result, value) {
						if(result === 'ok') {
							var lifetime = value;
							Ext.Ajax.request({
								url: restUrl + 'oidc/token/issue.json' + (lifetime.length ? '?length='+lifetime : ''),
								method: 'GET',
								scope: this,
								disableCaching: true,
								success: function(response) {
									var data = JSON.parse(response.responseText);
									Ext.Msg.alert('Token generated', 'Your new token is -> <b>' + data.raw_token + '</b>.<br>You will have to use this as your password when you connect with a client.<br>Make sure to keep it in a secure location before closing this window.<br>You will not be able to see it again.', Ext.getCmp('tokenGrid').reload());
								},
								failure: function(error) {
									console.error(error);
								}
							});
						}
					});
                }
			},{
				xtype: 'tbbutton',
				text: this.removeText,
				icon: this.removeIcon,
				scope: this,
				handler: function() {
					if(Ext.getCmp('tokenGrid').getSelectionModel().getSelected()) {
						var id = Ext.getCmp('tokenGrid').getSelectionModel().getSelected().id;
						Ext.Msg.confirm('Confirmation required', 'Are you sure you want to remove the token with id -> ' + id + '?', function(result) {
							if(result === 'yes') {
								Ext.Ajax.request({
									url: restUrl + 'oidc/token/invalidate?id=' + id,
									method: 'GET',
									scope: this,
									disableCaching: true,
									success: function(response) {
										if(response.responseText === 'OK') {
											Ext.getCmp('tokenGrid').reload();
											Ext.Msg.alert('Token removed', 'Your token with id -> ' + id + ' got removed.')
										}
									},
									failure: function(error) {}
								});
							}
						});
					}
				}
			},{
				xtype: 'tbseparator'
			},{
				xtype: 'tbbutton',
                text: this.reloadText,
                icon: this.reloadIcon,
                scope: this,
				handler: this.reload
			}],
			items: [{
				id: 'tokenGrid',
				xtype: 'tokenGrid',
				region: 'center',
				parentPanel: this
			},{
				id: 'tokenConfigPanel',
				xtype: 'tabpanel',
				activeTab: 0,
				height: 250,
				split: true,
				border: true,
				region: 'south',
				items: [{
					id: 'tokenConfig',
					xtype: 'tokenConfig'
				}]
			}]
		}

		Ext.apply(this, Ext.apply(this.initialConfig, config));
		cite.oidc.Panel.superclass.initComponent.apply(this, arguments);
	},

	getGrid: function() {
		if(!this.tokenGrid) {
			this.tokenGrid = Ext.getCmp('tokenGrid');
		}
		return this.tokenGrid;
	},

	reload: function() {
		this.getGrid().reload();
	}
});

Ext.reg('tokenPanel', cite.oidc.Panel);

//Keep browser history and state updated.
Sonia.History.register('tokenPanel', {
	onActivate: function(panel) {
		var token = null;
		var record = panel.getGrid().getSelectionModel().getSelected();
		if(record) {
			token = Sonia.History.createToken('tokenPanel', record.get('id'));
		} else {
			token = Sonia.History.createToken('tokenPanel');
		}
		return token;
	},
	waitAndSelect: function(grid, id) {
		setTimeout(function() {
			if (grid.ready) {
				grid.selectById(id);
			}
		}, 250);
	},
	onChange: function(id) {
		var panel = Ext.getCmp('tokenPanel');
		if(!panel) {
			cite.oidc.addTokensPanel();
			panel = Ext.getCmp('tokenPanel');
			if(id) {
				var selected = false;
				panel.getGrid().getStore().addListener("load", function() {
					if (!selected) {
						panel.getGrid().selectById(id);
						selected = true;
					}
				})
			}
		} else {
			main.addTab(panel);
			if (id) {
				var grid = panel.getGrid();
				if (grid.ready) {
					grid.selectById(id);
				} else {
					this.waitAndSelect(grid, id);
				}
			}
		}
	}
});
