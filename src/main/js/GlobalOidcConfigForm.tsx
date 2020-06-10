/*
 * MIT License
 *
 * Copyright (c) 2020-present Cloudogu GmbH and Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
import React from "react";
import { withTranslation, WithTranslation } from "react-i18next";
import { Links } from "@scm-manager/ui-types";
import { InputField, Checkbox, Subtitle } from "@scm-manager/ui-components";

type GlobalOidcConfig = {
  enabled: boolean;
  providerUrl: string;
  userIdentifier: string;
  adminRole: string;
  clientId: string;
  clientSecret: string;
  _links: Links;
};
// navposition
type Props = WithTranslation & {
  initialConfiguration: GlobalOidcConfig;
  onConfigurationChange: (p1: GlobalOidcConfig, p2: boolean) => void;
};

type State = GlobalOidcConfig & {
  configurationChanged?: boolean;
};

class GlobalOidcConfigForm extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      ...props.initialConfiguration
    };
  }

  render() {
    const { t } = this.props;
    return (
      <>
        {this.renderConfigChangedNotification()}
        <Checkbox
          name="enabled"
          label={t("scm-oidc-plugin.form.enabled")}
          helpText={t("scm-oidc-plugin.form.enabledHelp")}
          checked={this.state.enabled}
          onChange={this.valueChangeHandler}
        />
        <InputField
          name="providerUrl"
          label={t("scm-oidc-plugin.form.providerUrl")}
          helpText={t("scm-oidc-plugin.form.providerUrlHelp")}
          disabled={!this.state.enabled}
          value={this.state.providerUrl}
          onChange={this.valueChangeHandler}
          type="url"
        />
        <InputField
          name="userIdentifier"
          label={t("scm-oidc-plugin.form.userIdentifier")}
          helpText={t("scm-oidc-plugin.form.userIdentifierHelp")}
          disabled={!this.state.enabled}
          value={this.state.userIdentifier}
          onChange={this.valueChangeHandler}
         />
        <InputField
          name="adminRole"
          label={t("scm-oidc-plugin.form.adminRole")}
          helpText={t("scm-oidc-plugin.form.adminRoleHelp")}
          disabled={!this.state.enabled}
          value={this.state.adminRole}
          onChange={this.valueChangeHandler}
         />
        <InputField
          name="clientId"
          label={t("scm-oidc-plugin.form.clientId")}
          helpText={t("scm-oidc-plugin.form.clientIdHelp")}
          disabled={!this.state.enabled}
          value={this.state.clientId}
          onChange={this.valueChangeHandler}
         />
        <InputField
          name="clientSecret"
          label={t("scm-oidc-plugin.form.clientSecret")}
          helpText={t("scm-oidc-plugin.form.clientSecretHelp")}
          disabled={!this.state.enabled}
          value={this.state.clientSecret}
          onChange={this.valueChangeHandler}
         />
      </>
    );
  }

  renderConfigChangedNotification = () => {
    if (this.state.configurationChanged) {
      return (
        <div className="notification is-info">
          <button
            className="delete"
            onClick={() =>
              this.setState({
                ...this.state,
                configurationChanged: false
              })
            }
          />
          {this.props.t("scm-oidc-plugin.configurationChangedSuccess")}
        </div>
      );
    }
    return null;
  };

  valueChangeHandler = (value: string, name: string) => {
    this.setState(
      {
        [name]: value
      },
      () =>
        this.props.onConfigurationChange(
          {
            ...this.state
          },
          true
        )
    );
  };
}

export default withTranslation("plugins")(GlobalOidcConfigForm);