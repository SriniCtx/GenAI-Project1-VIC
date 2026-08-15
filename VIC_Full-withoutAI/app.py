"""Vulnerability Intelligence Center — local, rule-based vulnerability analytics."""
from datetime import datetime
from io import BytesIO
from pathlib import Path
import re
import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st

st.set_page_config("Vulnerability Intelligence Center", "🛡️", layout="wide")
REQUIRED = ["Asset_ID","Hostname","IP_Address","Operating_System","Business_Owner","Environment","Severity","QID","CVE","Vulnerability_Title","CVSS_v3_Score","First_Detected","Last_Detected","Days_Open","Patch_Available","Exploit_Available","Threat_Intel_Flag","Risk_Score","Status","Remediation_Action","Due_Date","Scanner_Source"]
ORDER = ["Critical", "High", "Medium", "Low"]
COLORS = {"Critical":"#dc2626", "High":"#f97316", "Medium":"#eab308", "Low":"#22c55e"}

@st.cache_data(ttl=900, show_spinner="Loading vulnerability data…")
def load_data(raw):
    df = pd.read_csv(BytesIO(raw)); missing = [c for c in REQUIRED if c not in df]
    if missing: raise ValueError("Missing required columns: " + ", ".join(missing))
    for c in ["CVSS_v3_Score", "Days_Open", "Risk_Score"]: df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)
    for c in ["First_Detected", "Last_Detected", "Due_Date"]: df[c] = pd.to_datetime(df[c], errors="coerce")
    text = [c for c in REQUIRED if c not in ["CVSS_v3_Score","Days_Open","Risk_Score","First_Detected","Last_Detected","Due_Date"]]
    df[text] = df[text].fillna("Unknown").astype(str).apply(lambda x: x.str.strip())
    df.Severity = df.Severity.str.title().where(lambda s: s.isin(ORDER), "Low"); df.Status = df.Status.str.title()
    df["Priority_Score"] = (df.CVSS_v3_Score * 40 + df.Days_Open + np.where(df.Severity.eq("Critical"),100,0) + np.where(df.Exploit_Available.str.casefold().eq("yes"),50,0) + np.where(df.Environment.str.casefold().eq("production"),50,0)).round(1)
    return df

def open_findings(df): return df[~df.Status.str.casefold().isin(["closed","resolved","remediated"])]
def sev(df, level): return int(df.Severity.eq(level).sum())
def asset_table(df, n=10):
    return df.groupby("Hostname").agg(**{"Total vulnerabilities":("Hostname","size"),"Critical count":("Severity",lambda s:(s=="Critical").sum()),"High count":("Severity",lambda s:(s=="High").sum()),"Average risk score":("Risk_Score","mean")}).reset_index().sort_values(["Total vulnerabilities","Average risk score"],ascending=False).head(n)
def owner_table(df):
    return df.groupby("Business_Owner").agg(**{"Total findings":("Business_Owner","size"),"Critical findings":("Severity",lambda s:(s=="Critical").sum()),"Average risk score":("Risk_Score","mean")}).reset_index().sort_values(["Critical findings","Average risk score"],ascending=False)
def cve_table(df, n=10): return df[df.CVE.ne("Unknown")].groupby("CVE").size().reset_index(name="Findings").nlargest(n,"Findings")

def security_posture(df):
    opened = open_findings(df); common = df.Vulnerability_Title.mode().iat[0] if len(df) else "N/A"; owner = owner_table(df).iloc[0].Business_Owner if len(df) else "N/A"
    return f"**Security posture summary**\n\nTotal vulnerabilities: **{len(df):,}** · Critical: **{sev(df,'Critical'):,}** · High: **{sev(df,'High'):,}** · Medium: **{sev(df,'Medium'):,}** · Open: **{len(opened):,}**. Average risk score: **{df.Risk_Score.mean():.1f}**; average days open: **{df.Days_Open.mean():.0f}**. Most common vulnerability: **{common}**. Top business owner: **{owner}**.\n\n**Recommended actions:** prioritize critical vulnerabilities, address production risks, and resolve aging vulnerabilities."
def executive_summary(df):
    p = df[df.Environment.str.casefold().eq("production")]; old = df[df.Days_Open.gt(90)]; rating = "HIGH" if sev(df,"Critical") or df.Risk_Score.mean() >= 70 else "MEDIUM" if sev(df,"High") else "LOW"
    return f"**Executive security summary**\n\n**Current environment:** {len(df):,} vulnerabilities, {sev(df,'Critical'):,} critical, {sev(df,'High'):,} high, {len(open_findings(df)):,} open.\n\n**Top risk areas:** 1. {sev(df,'Critical'):,} critical findings. 2. {len(p):,} production findings. 3. {len(old):,} findings older than 90 days.\n\n**Key business risks:** exploit exposure, production service disruption, and delayed remediation accountability.\n\n**Recommended actions:** 1. Patch exploitable critical production findings first. 2. Assign owners and dates to all SLA breaches. 3. Review residual risk weekly.\n\n**Overall risk rating: {rating}**"
def patching_plan(df): return "**Top remediation targets:** prioritize critical, exploitable, and production findings with prolonged exposure. Validate patches in change control and verify closure by rescan.", open_findings(df).nlargest(10,"Priority_Score")
def old_findings(df): return "**Aging-risk assessment:** these have the longest open exposure. Escalate critical or exploitable items and require dated remediation plans.", open_findings(df).nlargest(20,"Days_Open")
def production_risks(df):
    p=df[df.Environment.str.casefold().eq("production")]; e=p[p.Exploit_Available.str.casefold().eq("yes")]
    return f"**Production risk:** {len(p):,} findings, {sev(p,'Critical'):,} critical, and {len(e):,} with known exploits. Schedule urgent remediation with service owners.",p.nlargest(15,"Priority_Score")
def sla_risks(df):
    b=df[((df.Severity=="Critical")&(df.Days_Open>30))|((df.Severity=="High")&(df.Days_Open>60))|((df.Severity=="Medium")&(df.Days_Open>90))]
    return f"**SLA risks:** {sev(b,'Critical'):,} critical, {sev(b,'High'):,} high, and {sev(b,'Medium'):,} medium breaches. Escalate the highest-breach owners and assets.",b.nlargest(20,"Days_Open")

# Explicit analytics API used by the intelligence assistant and available for reuse.
def generate_security_posture(df): return security_posture(df)
def generate_executive_summary(df): return executive_summary(df)
def generate_owner_summary(df):
    return f"**Owner analysis:** {owner_table(df).iloc[0].Business_Owner if len(df) else 'N/A'} has the highest risk concentration. Confirm accountable remediation leads.", owner_table(df)
def generate_patching_plan(df): return patching_plan(df)
def generate_top_assets(df): return "**Most vulnerable servers:** focus remediation windows on the assets below; address critical findings first.", asset_table(df)
def generate_cve_summary(df):
    return f"**CVE concentration:** most common vulnerability title: **{df.Vulnerability_Title.mode().iat[0] if len(df) else 'N/A'}**. Standardize mitigation for recurring CVEs.", cve_table(df)
def generate_oldest_findings(df): return old_findings(df)
def generate_production_risk_summary(df): return production_risks(df)
def generate_sla_summary(df): return sla_risks(df)

def plot(fig, title):
    fig.update_layout(title=title, template="plotly_dark", margin=dict(l=10,r=10,t=45,b=10), legend_title_text="")
    st.plotly_chart(fig, width="stretch")

def global_filters(df):
    st.sidebar.header("Data controls"); st.sidebar.caption(f"**Records:** {len(df):,}"); st.sidebar.caption(f"**Last refresh:** {datetime.now():%d %b %Y, %H:%M}")
    choices={}
    for c,label in [("Severity","Severity"),("Environment","Environment"),("Business_Owner","Business owner"),("Operating_System","Operating system"),("Status","Status")]:
        opts=sorted(df[c].unique()); choices[c]=st.sidebar.multiselect(label,opts,default=opts,key="global_"+c)
    result=df.copy()
    for c,v in choices.items(): result=result[result[c].isin(v)]
    changed=[f"{c.replace('_',' ')} ({len(v)})" for c,v in choices.items() if len(v)<df[c].nunique()]
    st.sidebar.caption("**Active filters:** "+(", ".join(changed) if changed else "None")); st.sidebar.info("Use the tabs to review posture, investigate findings, prioritize remediation, or ask the rule-based assistant.",icon=":material/tips_and_updates:")
    return result

def dashboard(df):
    opened=open_findings(df); m=[("Total vulnerabilities",len(df)),("Critical",sev(df,"Critical")),("High",sev(df,"High")),("Medium",sev(df,"Medium")),("Open findings",len(opened)),("Closed findings",len(df)-len(opened)),("Average risk",f"{df.Risk_Score.mean():.1f}"),("Average days open",f"{df.Days_Open.mean():.0f}")]
    for row in (m[:4],m[4:]):
        with st.container(horizontal=True):
            for label,value in row: st.metric(label,value,border=True)
    a,b=st.columns(2)
    with a: plot(px.pie(df,names="Severity",color="Severity",color_discrete_map=COLORS),"Severity distribution")
    with b: plot(px.bar(df.groupby("Environment").size().reset_index(name="Findings"),x="Environment",y="Findings",color="Environment"),"Vulnerabilities by environment")
    a,b=st.columns(2)
    with a: plot(px.bar(asset_table(df),x="Total vulnerabilities",y="Hostname",orientation="h",color="Average risk score",color_continuous_scale="Reds"),"Top 10 vulnerable assets")
    with b: plot(px.bar(df.groupby("Vulnerability_Title").size().reset_index(name="Findings").nlargest(10,"Findings"),x="Findings",y="Vulnerability_Title",orientation="h"),"Top 10 vulnerability types")
    a,b=st.columns(2)
    with a: plot(px.histogram(df,x="Risk_Score",nbins=20,color="Severity",color_discrete_map=COLORS),"Risk score distribution")
    with b: plot(px.bar(df.groupby("Business_Owner").size().reset_index(name="Findings").sort_values("Findings"),x="Findings",y="Business_Owner",orientation="h"),"Vulnerabilities by business owner")
    a,b=st.columns(2)
    with a: plot(px.pie(pd.DataFrame({"Status":["Open","Closed"],"Findings":[len(opened),len(df)-len(opened)]}),names="Status",values="Findings",color="Status",color_discrete_map={"Open":"#f97316","Closed":"#22c55e"}),"Open vs closed findings")
    with b: plot(px.bar(cve_table(df),x="Findings",y="CVE",orientation="h"),"Top 10 CVEs")

def explorer(df):
    st.subheader("Investigate findings"); cols=st.columns(3)
    definitions=[("Severity",ORDER),("Environment",sorted(df.Environment.unique())),("Business_Owner",sorted(df.Business_Owner.unique())),("Operating_System",sorted(df.Operating_System.unique())),("Status",sorted(df.Status.unique())),("CVE",sorted(df.CVE.unique()))]
    selected={}
    for i,(c,opts) in enumerate(definitions): selected[c]=cols[i%3].multiselect(c.replace("_"," "),opts,default=opts,key="explore_"+c)
    result=df.copy()
    for c,values in selected.items(): result=result[result[c].isin(values)]
    query=st.text_input("Search hostname, asset ID, or IP address",placeholder="e.g. server-01 or 10.0.0.5")
    if query: result=result[result[["Hostname","Asset_ID","IP_Address"]].astype(str).apply(lambda x:x.str.contains(re.escape(query),case=False,na=False)).any(axis=1)]
    st.download_button("Download filtered CSV",result.to_csv(index=False).encode(),"vic_filtered_findings.csv","text/csv",icon=":material/download:")
    st.dataframe(result.nlargest(len(result),"Priority_Score"),hide_index=True,height=420,column_config={"Priority_Score":st.column_config.NumberColumn("Priority score",format="%.1f"),"Risk_Score":st.column_config.NumberColumn("Risk score",format="%.1f")})
    st.subheader("Asset drill-down"); host=st.selectbox("Select a hostname",sorted(result.Hostname.unique()) if len(result) else ["No matching assets"]); asset=result[result.Hostname.eq(host)]
    if len(asset):
        r=asset.iloc[0]; metrics=[("Asset ID",r.Asset_ID),("Hostname",r.Hostname),("IP address",r.IP_Address),("Business owner",r.Business_Owner),("Environment",r.Environment),("Operating system",r.Operating_System),("Total vulnerabilities",len(asset)),("Critical count",sev(asset,"Critical")),("High count",sev(asset,"High")),("Average risk",f"{asset.Risk_Score.mean():.1f}")]
        with st.container(horizontal=True):
            for label,value in metrics: st.metric(label,value,border=True)
        st.dataframe(asset.nlargest(len(asset),"Priority_Score"),hide_index=True)

def prioritizer(df):
    active=open_findings(df); st.subheader("Risk prioritisation"); st.caption("Priority score = CVSS v3 × 40 + days open + 100 (critical) + 50 (known exploit) + 50 (production).")
    st.dataframe(active.nlargest(20,"Priority_Score"),hide_index=True,column_config={"Priority_Score":st.column_config.NumberColumn("Priority score",format="%.1f")})
    a,b=st.columns(2)
    with a: st.markdown("#### Highest-risk assets"); st.dataframe(asset_table(active),hide_index=True)
    with b: st.markdown("#### Highest-risk business owners"); st.dataframe(owner_table(active).head(10),hide_index=True)
    a,b,c=st.columns(3); a.metric("Findings older than 90 days",int(active.Days_Open.gt(90).sum()),border=True); b.metric("Critical with known exploits",int(((active.Severity=="Critical")&active.Exploit_Available.str.casefold().eq("yes")).sum()),border=True); c.metric("Production risks",int(active.Environment.str.casefold().eq("production").sum()),border=True)
    if st.button("Generate action plan",type="primary",icon=":material/assignment:"):
        st.markdown(executive_summary(active)); st.markdown("**Suggested 30-day action plan:** Days 1–7: eliminate exploitable critical production risks. Days 8–21: remediate high-risk aging findings. Days 22–30: verify closure, resolve exceptions, and report residual risk.")

def intelligence(df):
    st.subheader("VIC intelligence assistant"); st.caption("Local rule-based analytics and narrative generation — no external AI services or APIs.")
    q={"Summarize security posture":lambda d:(generate_security_posture(d),None),"What should be patched first?":generate_patching_plan,"Show most vulnerable servers":generate_top_assets,"Show critical vulnerabilities":lambda d:(f"**Critical vulnerabilities:** {sev(d,'Critical'):,} findings. Prioritize exploitable and aging critical findings immediately.",d[d.Severity.eq("Critical")].nlargest(20,"Priority_Score")),"Show oldest vulnerabilities":generate_oldest_findings,"Show top CVEs":generate_cve_summary,"Show vulnerabilities by owner":generate_owner_summary,"Show production risks":generate_production_risk_summary,"Show SLA risks":generate_sla_summary,"Generate executive summary":lambda d:(generate_executive_summary(d),None)}
    st.markdown("**Suggested questions:** " + " · ".join(q)); selected=st.selectbox("Select a question",list(q))
    if st.button("Ask VIC",type="primary",icon=":material/send:"):
        narrative,table=q[selected](df)
        with st.chat_message("assistant",avatar="🛡️"):
            st.markdown(narrative)
            if table is not None: st.dataframe(table,hide_index=True)
    a,b=st.columns(2)
    with a:
        with st.container(border=True): st.markdown("**Executive snapshot**"); st.markdown(executive_summary(df))
    with b:
        with st.container(border=True): st.markdown("**Key insights**"); st.markdown(security_posture(df))

def main():
    st.title("🛡️ Vulnerability Intelligence Center"); st.caption("Transforming Vulnerability Data into Actionable Intelligence")
    with st.sidebar: upload=st.file_uploader("Upload Qualys/Panaseer CSV",type="csv",help="Expected: vulnerability export with the VIC schema.")
    try: df=load_data(upload.getvalue() if upload else Path("data/Qualys_Panaseer_Server_Vulnerabilities_1000Rows.csv").read_bytes())
    except (OSError,ValueError,pd.errors.ParserError) as err: st.error(f"Unable to load vulnerability data: {err}"); st.stop()
    filtered=global_filters(df); st.caption(f"Showing **{len(filtered):,}** of **{len(df):,}** findings.")
    tabs=st.tabs(["Security posture","Vulnerability explorer","Remediation prioritizer","VIC intelligence assistant"])
    with tabs[0]: dashboard(filtered)
    with tabs[1]: explorer(filtered)
    with tabs[2]: prioritizer(filtered)
    with tabs[3]: intelligence(filtered)
if __name__ == "__main__": main()
