#include <libyang/libyang.h>
#include <sysrepo.h>
#include <sysrepo/xpath.h>

LY_ERR mountpoint_ext_data_clb(
    const struct lysc_ext_instance *ext,
    void *user_data,
    void **ext_data,
    ly_bool *ext_data_free);

int main(){
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *session;
    sr_subscription_ctx_t *subscription;

    int err = sr_connect(SR_CONN_DEFAULT, &conn);
    if (err != SR_ERR_OK){
        printf("connection error %d\n", err);
        return 1;
    }
    
    err = sr_session_start(conn, SR_DS_RUNNING, &session);
    if (err != SR_ERR_OK) {
        printf("session error %d\n", err);
        return 1;
    }

    struct ly_ctx *ctx = sr_acquire_context(conn);
    if (ctx == NULL) {
        
        return 1;
    }

    sr_set_ext_data_cb(conn, mountpoint_ext_data_clb, (void*) ctx);

    struct lyd_node** parent;
    LY_ERR lyErr = lyd_new_path(NULL, ctx, "/bbf-device-aggregation:devices", NULL, 0, parent);
    if (err != LY_SUCCESS) {
        printf("parent creation error %d\n", lyErr);
        return 1;
    }

    if (parent == NULL) {
        printf("null created node\n");
    }

    lyErr = lyd_new_path(*parent, ctx, "/bbf-device-aggregation:devices/device[name='a07dcc30-1107-4754-b513-09b1d389508c']/data/ietf-hardware:hardware/component[name='a07dcc30-1107-4754-b513-09b1d389508c']/mfg-name", "test1", 0, NULL);
    if (err != LY_SUCCESS) {
        printf("first creation error %d\n", lyErr);
        return 1;
    }

    lyErr = lyd_new_path(*parent, ctx, "/bbf-device-aggregation:devices/device[name='a07dcc30-1107-4754-b513-09b1d389508c']/data/ietf-hardware:hardware/component[name='a07dcc30-1107-4754-b513-09b1d389508c']/model-name", "test2", 0, NULL);
    if (err != LY_SUCCESS) {
        printf("second creation error %d\n", lyErr);
        return 1;
    }

    lyd_free_all(*parent);

    sr_release_context(conn);

    err = sr_session_stop(session);
    if (err != SR_ERR_OK) {
        printf("cleanup session error %d\n", err);
        return 1;
    }
    err = sr_disconnect(conn);
    if (err != SR_ERR_OK) {
        printf("cleanup connection error %d\n", err);
        return 1;
    }
    return 0;
}

LY_ERR mountpoint_ext_data_clb(
    const struct lysc_ext_instance *ext,
    void *user_data,
    void **ext_data,
    ly_bool *ext_data_free)
{   
    const char* data = "<schema-mounts xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-schema-mount\">\
  <mount-point>\
    <module>bbf-device-aggregation</module>\
    <label>device-yang-library</label>\
    <config>true</config>\
    <inline/>\
  </mount-point>\
</schema-mounts><yang-library xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-library\">\
  <module-set>\
    <name>complete</name>\
    <module>\
      <name>yang</name>\
      <revision>2021-04-07</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:1</namespace>\
    </module>\
    <module>\
      <name>ietf-yang-schema-mount</name>\
      <revision>2019-01-14</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-yang-schema-mount</namespace>\
    </module>\
    <module>\
      <name>sysrepo</name>\
      <revision>2021-10-08</revision>\
      <namespace>http://www.sysrepo.org/yang/sysrepo</namespace>\
    </module>\
    <module>\
      <name>ietf-datastores</name>\
      <revision>2018-02-14</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-datastores</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-datastores@2018-02-14.yang</location>\
    </module>\
    <module>\
      <name>ietf-yang-library</name>\
      <revision>2019-01-04</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-yang-library</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-yang-library@2019-01-04.yang</location>\
    </module>\
    <module>\
      <name>sysrepo-monitoring</name>\
      <revision>2021-07-29</revision>\
      <namespace>http://www.sysrepo.org/yang/sysrepo-monitoring</namespace>\
      <location>file:///etc/sysrepo/yang/sysrepo-monitoring@2021-07-29.yang</location>\
    </module>\
    <module>\
      <name>sysrepo-plugind</name>\
      <revision>2022-03-10</revision>\
      <namespace>urn:sysrepo:plugind</namespace>\
      <location>file:///etc/sysrepo/yang/sysrepo-plugind@2022-03-10.yang</location>\
    </module>\
    <module>\
      <name>ietf-netconf-acm</name>\
      <revision>2018-02-14</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-acm</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-netconf-acm@2018-02-14.yang</location>\
    </module>\
    <module>\
      <name>ietf-netconf</name>\
      <revision>2013-09-29</revision>\
      <namespace>urn:ietf:params:xml:ns:netconf:base:1.0</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-netconf@2013-09-29.yang</location>\
      <feature>writable-running</feature>\
      <feature>candidate</feature>\
      <feature>confirmed-commit</feature>\
      <feature>rollback-on-error</feature>\
      <feature>validate</feature>\
      <feature>startup</feature>\
      <feature>url</feature>\
      <feature>xpath</feature>\
    </module>\
    <module>\
      <name>ietf-netconf-with-defaults</name>\
      <revision>2011-06-01</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-netconf-with-defaults@2011-06-01.yang</location>\
    </module>\
    <module>\
      <name>ietf-netconf-notifications</name>\
      <revision>2012-02-06</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-notifications</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-netconf-notifications@2012-02-06.yang</location>\
    </module>\
    <module>\
      <name>ietf-origin</name>\
      <revision>2018-02-14</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-origin</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-origin@2018-02-14.yang</location>\
    </module>\
    <module>\
      <name>ietf-netconf-monitoring</name>\
      <revision>2010-10-04</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-netconf-monitoring@2010-10-04.yang</location>\
    </module>\
    <module>\
      <name>ietf-netconf-nmda</name>\
      <revision>2019-01-07</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-nmda</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-netconf-nmda@2019-01-07.yang</location>\
      <feature>origin</feature>\
      <feature>with-defaults</feature>\
    </module>\
    <module>\
      <name>nc-notifications</name>\
      <revision>2008-07-14</revision>\
      <namespace>urn:ietf:params:xml:ns:netmod:notification</namespace>\
      <location>file:///etc/sysrepo/yang/nc-notifications@2008-07-14.yang</location>\
    </module>\
    <module>\
      <name>notifications</name>\
      <revision>2008-07-14</revision>\
      <namespace>urn:ietf:params:xml:ns:netconf:notification:1.0</namespace>\
      <location>file:///etc/sysrepo/yang/notifications@2008-07-14.yang</location>\
    </module>\
    <module>\
      <name>ietf-x509-cert-to-name</name>\
      <revision>2014-12-10</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-x509-cert-to-name</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-x509-cert-to-name@2014-12-10.yang</location>\
    </module>\
    <module>\
      <name>ietf-crypto-types</name>\
      <revision>2019-07-02</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-crypto-types</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-crypto-types@2019-07-02.yang</location>\
    </module>\
    <module>\
      <name>ietf-keystore</name>\
      <revision>2019-07-02</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-keystore</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-keystore@2019-07-02.yang</location>\
      <feature>keystore-supported</feature>\
    </module>\
    <module>\
      <name>ietf-truststore</name>\
      <revision>2019-07-02</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-truststore</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-truststore@2019-07-02.yang</location>\
      <feature>truststore-supported</feature>\
      <feature>x509-certificates</feature>\
    </module>\
    <module>\
      <name>ietf-tcp-common</name>\
      <revision>2019-07-02</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-tcp-common</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-tcp-common@2019-07-02.yang</location>\
      <feature>keepalives-supported</feature>\
    </module>\
    <module>\
      <name>ietf-ssh-server</name>\
      <revision>2019-07-02</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-ssh-server</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-ssh-server@2019-07-02.yang</location>\
      <feature>local-client-auth-supported</feature>\
    </module>\
    <module>\
      <name>ietf-tls-server</name>\
      <revision>2019-07-02</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-tls-server</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-tls-server@2019-07-02.yang</location>\
      <feature>local-client-auth-supported</feature>\
    </module>\
    <module>\
      <name>ietf-netconf-server</name>\
      <revision>2019-07-02</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-server</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-netconf-server@2019-07-02.yang</location>\
      <feature>ssh-listen</feature>\
      <feature>tls-listen</feature>\
      <feature>ssh-call-home</feature>\
      <feature>tls-call-home</feature>\
    </module>\
    <module>\
      <name>ietf-interfaces</name>\
      <revision>2018-02-20</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-interfaces</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-interfaces@2018-02-20.yang</location>\
    </module>\
    <module>\
      <name>ietf-ip</name>\
      <revision>2018-02-22</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-ip</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-ip@2018-02-22.yang</location>\
    </module>\
    <module>\
      <name>ietf-network-instance</name>\
      <revision>2019-01-21</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-network-instance</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-network-instance@2019-01-21.yang</location>\
    </module>\
    <module>\
      <name>ietf-subscribed-notifications</name>\
      <revision>2019-09-09</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-subscribed-notifications@2019-09-09.yang</location>\
      <feature>encode-xml</feature>\
      <feature>replay</feature>\
      <feature>subtree</feature>\
      <feature>xpath</feature>\
    </module>\
    <module>\
      <name>ietf-yang-push</name>\
      <revision>2019-09-09</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-yang-push</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-yang-push@2019-09-09.yang</location>\
      <feature>on-change</feature>\
    </module>\
    <module>\
      <name>bbf-device-aggregation</name>\
      <revision>2022-03-01</revision>\
      <namespace>urn:bbf:yang:bbf-device-aggregation</namespace>\
      <location>file:///etc/sysrepo/yang/bbf-device-aggregation@2022-03-01.yang</location>\
    </module>\
    <module>\
      <name>bbf-yang-types</name>\
      <revision>2022-03-01</revision>\
      <namespace>urn:bbf:yang:bbf-yang-types</namespace>\
      <location>file:///etc/sysrepo/yang/bbf-yang-types@2022-03-01.yang</location>\
    </module>\
    <module>\
      <name>bbf-device-types</name>\
      <revision>2021-06-02</revision>\
      <namespace>urn:bbf:yang:bbf-device-types</namespace>\
      <location>file:///etc/sysrepo/yang/bbf-device-types@2021-06-02.yang</location>\
    </module>\
    <module>\
      <name>iana-hardware</name>\
      <revision>2018-03-13</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:iana-hardware</namespace>\
      <location>file:///etc/sysrepo/yang/iana-hardware@2018-03-13.yang</location>\
    </module>\
    <module>\
      <name>ietf-hardware</name>\
      <revision>2018-03-13</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-hardware</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-hardware@2018-03-13.yang</location>\
      <feature>hardware-state</feature>\
    </module>\
    <import-only-module>\
      <name>ietf-yang-metadata</name>\
      <revision>2016-08-05</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-yang-metadata</namespace>\
    </import-only-module>\
    <import-only-module>\
      <name>ietf-inet-types</name>\
      <revision>2013-07-15</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-inet-types</namespace>\
    </import-only-module>\
    <import-only-module>\
      <name>ietf-yang-types</name>\
      <revision>2013-07-15</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-yang-types</namespace>\
    </import-only-module>\
    <import-only-module>\
      <name>ietf-ssh-common</name>\
      <revision>2019-07-02</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-ssh-common</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-ssh-common@2019-07-02.yang</location>\
    </import-only-module>\
    <import-only-module>\
      <name>iana-crypt-hash</name>\
      <revision>2014-08-06</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:iana-crypt-hash</namespace>\
      <location>file:///etc/sysrepo/yang/iana-crypt-hash@2014-08-06.yang</location>\
    </import-only-module>\
    <import-only-module>\
      <name>ietf-tls-common</name>\
      <revision>2019-07-02</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-tls-common</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-tls-common@2019-07-02.yang</location>\
    </import-only-module>\
    <import-only-module>\
      <name>ietf-tcp-client</name>\
      <revision>2019-07-02</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-tcp-client</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-tcp-client@2019-07-02.yang</location>\
    </import-only-module>\
    <import-only-module>\
      <name>ietf-tcp-server</name>\
      <revision>2019-07-02</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-tcp-server</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-tcp-server@2019-07-02.yang</location>\
    </import-only-module>\
    <import-only-module>\
      <name>ietf-restconf</name>\
      <revision>2017-01-26</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-restconf</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-restconf@2017-01-26.yang</location>\
    </import-only-module>\
    <import-only-module>\
      <name>ietf-yang-patch</name>\
      <revision>2017-02-22</revision>\
      <namespace>urn:ietf:params:xml:ns:yang:ietf-yang-patch</namespace>\
      <location>file:///etc/sysrepo/yang/ietf-yang-patch@2017-02-22.yang</location>\
    </import-only-module>\
  </module-set>\
  <schema>\
    <name>complete</name>\
    <module-set>complete</module-set>\
  </schema>\
  <datastore>\
    <name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>\
    <schema>complete</schema>\
  </datastore>\
  <datastore>\
    <name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:candidate</name>\
    <schema>complete</schema>\
  </datastore>\
  <datastore>\
    <name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>\
    <schema>complete</schema>\
  </datastore>\
  <datastore>\
    <name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:operational</name>\
    <schema>complete</schema>\
  </datastore>\
  <content-id>1</content-id>\
</yang-library>\
<modules-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-library\">\
  <module-set-id>1</module-set-id>\
  <module>\
    <name>ietf-yang-metadata</name>\
    <revision>2016-08-05</revision>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-yang-metadata</namespace>\
    <conformance-type>import</conformance-type>\
  </module>\
  <module>\
    <name>yang</name>\
    <revision>2021-04-07</revision>\
    <namespace>urn:ietf:params:xml:ns:yang:1</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-inet-types</name>\
    <revision>2013-07-15</revision>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-inet-types</namespace>\
    <conformance-type>import</conformance-type>\
  </module>\
  <module>\
    <name>ietf-yang-types</name>\
    <revision>2013-07-15</revision>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-yang-types</namespace>\
    <conformance-type>import</conformance-type>\
  </module>\
  <module>\
    <name>ietf-yang-schema-mount</name>\
    <revision>2019-01-14</revision>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-yang-schema-mount</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>sysrepo</name>\
    <revision>2021-10-08</revision>\
    <namespace>http://www.sysrepo.org/yang/sysrepo</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-datastores</name>\
    <revision>2018-02-14</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-datastores@2018-02-14.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-datastores</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-yang-library</name>\
    <revision>2019-01-04</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-yang-library@2019-01-04.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-yang-library</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>sysrepo-monitoring</name>\
    <revision>2021-07-29</revision>\
    <schema>file:///etc/sysrepo/yang/sysrepo-monitoring@2021-07-29.yang</schema>\
    <namespace>http://www.sysrepo.org/yang/sysrepo-monitoring</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>sysrepo-plugind</name>\
    <revision>2022-03-10</revision>\
    <schema>file:///etc/sysrepo/yang/sysrepo-plugind@2022-03-10.yang</schema>\
    <namespace>urn:sysrepo:plugind</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-netconf-acm</name>\
    <revision>2018-02-14</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-netconf-acm@2018-02-14.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-acm</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-netconf</name>\
    <revision>2013-09-29</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-netconf@2013-09-29.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:netconf:base:1.0</namespace>\
    <feature>writable-running</feature>\
    <feature>candidate</feature>\
    <feature>confirmed-commit</feature>\
    <feature>rollback-on-error</feature>\
    <feature>validate</feature>\
    <feature>startup</feature>\
    <feature>url</feature>\
    <feature>xpath</feature>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-netconf-with-defaults</name>\
    <revision>2011-06-01</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-netconf-with-defaults@2011-06-01.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-netconf-notifications</name>\
    <revision>2012-02-06</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-netconf-notifications@2012-02-06.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-notifications</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-origin</name>\
    <revision>2018-02-14</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-origin@2018-02-14.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-origin</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-netconf-monitoring</name>\
    <revision>2010-10-04</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-netconf-monitoring@2010-10-04.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-netconf-nmda</name>\
    <revision>2019-01-07</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-netconf-nmda@2019-01-07.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-nmda</namespace>\
    <feature>origin</feature>\
    <feature>with-defaults</feature>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>nc-notifications</name>\
    <revision>2008-07-14</revision>\
    <schema>file:///etc/sysrepo/yang/nc-notifications@2008-07-14.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:netmod:notification</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>notifications</name>\
    <revision>2008-07-14</revision>\
    <schema>file:///etc/sysrepo/yang/notifications@2008-07-14.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:netconf:notification:1.0</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-x509-cert-to-name</name>\
    <revision>2014-12-10</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-x509-cert-to-name@2014-12-10.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-x509-cert-to-name</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-crypto-types</name>\
    <revision>2019-07-02</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-crypto-types@2019-07-02.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-crypto-types</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-keystore</name>\
    <revision>2019-07-02</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-keystore@2019-07-02.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-keystore</namespace>\
    <feature>keystore-supported</feature>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-truststore</name>\
    <revision>2019-07-02</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-truststore@2019-07-02.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-truststore</namespace>\
    <feature>truststore-supported</feature>\
    <feature>x509-certificates</feature>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-tcp-common</name>\
    <revision>2019-07-02</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-tcp-common@2019-07-02.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-tcp-common</namespace>\
    <feature>keepalives-supported</feature>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-ssh-server</name>\
    <revision>2019-07-02</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-ssh-server@2019-07-02.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-ssh-server</namespace>\
    <feature>local-client-auth-supported</feature>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-ssh-common</name>\
    <revision>2019-07-02</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-ssh-common@2019-07-02.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-ssh-common</namespace>\
    <conformance-type>import</conformance-type>\
  </module>\
  <module>\
    <name>iana-crypt-hash</name>\
    <revision>2014-08-06</revision>\
    <schema>file:///etc/sysrepo/yang/iana-crypt-hash@2014-08-06.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:iana-crypt-hash</namespace>\
    <conformance-type>import</conformance-type>\
  </module>\
  <module>\
    <name>ietf-tls-server</name>\
    <revision>2019-07-02</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-tls-server@2019-07-02.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-tls-server</namespace>\
    <feature>local-client-auth-supported</feature>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-tls-common</name>\
    <revision>2019-07-02</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-tls-common@2019-07-02.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-tls-common</namespace>\
    <conformance-type>import</conformance-type>\
  </module>\
  <module>\
    <name>ietf-netconf-server</name>\
    <revision>2019-07-02</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-netconf-server@2019-07-02.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-server</namespace>\
    <feature>ssh-listen</feature>\
    <feature>tls-listen</feature>\
    <feature>ssh-call-home</feature>\
    <feature>tls-call-home</feature>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-tcp-client</name>\
    <revision>2019-07-02</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-tcp-client@2019-07-02.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-tcp-client</namespace>\
    <conformance-type>import</conformance-type>\
  </module>\
  <module>\
    <name>ietf-tcp-server</name>\
    <revision>2019-07-02</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-tcp-server@2019-07-02.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-tcp-server</namespace>\
    <conformance-type>import</conformance-type>\
  </module>\
  <module>\
    <name>ietf-interfaces</name>\
    <revision>2018-02-20</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-interfaces@2018-02-20.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-interfaces</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-ip</name>\
    <revision>2018-02-22</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-ip@2018-02-22.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-ip</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-network-instance</name>\
    <revision>2019-01-21</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-network-instance@2019-01-21.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-network-instance</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-subscribed-notifications</name>\
    <revision>2019-09-09</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-subscribed-notifications@2019-09-09.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications</namespace>\
    <feature>encode-xml</feature>\
    <feature>replay</feature>\
    <feature>subtree</feature>\
    <feature>xpath</feature>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-restconf</name>\
    <revision>2017-01-26</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-restconf@2017-01-26.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-restconf</namespace>\
    <conformance-type>import</conformance-type>\
  </module>\
  <module>\
    <name>ietf-yang-push</name>\
    <revision>2019-09-09</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-yang-push@2019-09-09.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-yang-push</namespace>\
    <feature>on-change</feature>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-yang-patch</name>\
    <revision>2017-02-22</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-yang-patch@2017-02-22.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-yang-patch</namespace>\
    <conformance-type>import</conformance-type>\
  </module>\
  <module>\
    <name>bbf-device-aggregation</name>\
    <revision>2022-03-01</revision>\
    <schema>file:///etc/sysrepo/yang/bbf-device-aggregation@2022-03-01.yang</schema>\
    <namespace>urn:bbf:yang:bbf-device-aggregation</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>bbf-yang-types</name>\
    <revision>2022-03-01</revision>\
    <schema>file:///etc/sysrepo/yang/bbf-yang-types@2022-03-01.yang</schema>\
    <namespace>urn:bbf:yang:bbf-yang-types</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>bbf-device-types</name>\
    <revision>2021-06-02</revision>\
    <schema>file:///etc/sysrepo/yang/bbf-device-types@2021-06-02.yang</schema>\
    <namespace>urn:bbf:yang:bbf-device-types</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>iana-hardware</name>\
    <revision>2018-03-13</revision>\
    <schema>file:///etc/sysrepo/yang/iana-hardware@2018-03-13.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:iana-hardware</namespace>\
    <conformance-type>implement</conformance-type>\
  </module>\
  <module>\
    <name>ietf-hardware</name>\
    <revision>2018-03-13</revision>\
    <schema>file:///etc/sysrepo/yang/ietf-hardware@2018-03-13.yang</schema>\
    <namespace>urn:ietf:params:xml:ns:yang:ietf-hardware</namespace>\
    <feature>hardware-state</feature>\
    <conformance-type>implement</conformance-type>\
  </module>\
</modules-state>\
";

    struct ly_ctx *ctx = (struct ly_ctx*) user_data;

    lyd_parse_data_mem(ctx, data, LYD_XML, LYD_PARSE_STRICT, LYD_VALIDATE_PRESENT, ext_data);
    *ext_data_free = 1;
    return LY_SUCCESS;
}