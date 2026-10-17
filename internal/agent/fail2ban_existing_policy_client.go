package agent

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/secure"
)

// The official client includes general server settings even for a named reload.
// Restrict its generated stream before it reaches the official transport. All
// code and accepted verbs are fixed; the only target is the adopted jail.
// Isolated Python keeps the distribution's global site for its existing
// Fail2ban installation, but excludes user site, PYTHONPATH and the working dir.
const fail2banExistingPolicyClient = `import sys,os
from fail2ban.version import version
if version!='1.1.1':
 raise ValueError('unsupported official Fail2ban library version')
from fail2ban.client.configurator import Configurator
from fail2ban.client.configparserinc import SafeConfigParserWithIncludes
from fail2ban.client.fail2banclient import exec_command_line
jail,client,root=sys.argv[1:4]
root=os.path.realpath(root)
read=SafeConfigParserWithIncludes._getSharedSCPWI
def confined(self,resource):
 if not isinstance(resource,str) or os.path.commonpath((root,os.path.realpath(resource)))!=root:
  raise ValueError('configuration include is outside frozen candidate')
 return read(self,resource)
SafeConfigParserWithIncludes._getSharedSCPWI=confined
original=Configurator.getConfigStream
options=Configurator.getOptions
def selected_options(self,section=None,updateMainOpt=None,ignoreWrong=True):
 if section is not None and section!=jail:
  raise ValueError('configuration selection is outside adopted jail')
 return options(self,jail,updateMainOpt,False)
Configurator.getOptions=selected_options
def scoped(self):
 result=[]
 for c in original(self):
  if not isinstance(c,list) or len(c)<2:
   raise ValueError('invalid official configuration stream')
  if c[0]=='set' and len(c)==3 and c[1] in ('thread','syslogsocket','loglevel','logtarget','allowipv6','dbfile','dbmaxmatches','dbpurgeage'):
   continue
  if c[0] not in ('add','set','multi-set','start') or c[1]!=jail:
   raise ValueError('configuration stream is outside adopted jail')
  result.append(c)
 return result
Configurator.getConfigStream=scoped
sys.argv=[client]+sys.argv[4:]
exec_command_line(sys.argv)
`

func fail2banExistingPolicyClientArgs(p fail2banProgram, c *fail2banExistingPolicyCapture, dir, socket, verb string) []string {
	args := []string{"-I", "-B", "-c", fail2banExistingPolicyClient, c.Plan.Name, p.tool.Resolved, dir, "-c", dir, "--timeout", "10"}
	args = append(args, fail2banReadArgs(socket, verb)...)
	if verb == "reload" {
		args = append(args, "--if-exists", c.Plan.Name)
	}
	return args
}

func prepareFail2banExistingPolicyClient(ctx context.Context, data string, c *fail2banExistingPolicyCapture, evidence fail2banExistingRuntimeEvidence) (fail2ban.Tool, string, error) {
	var empty fail2ban.Tool
	started, err := fail2banExistingStarted(ctx, &evidence.Capture.Binding, evidence.Live)
	if err != nil {
		return empty, "", err
	}
	python, _, err := fail2banExistingClockProgram(evidence.Live, started)
	if err != nil {
		return empty, "", err
	}
	root := filepath.Join(fail2banExistingDir(data), "policy-configs")
	if err = secure.RootDirectory(root, 0700); err != nil {
		return empty, "", err
	}
	dir := filepath.Join(root, c.After.ID)
	if err = secure.RootDirectory(dir, 0700); err != nil {
		return empty, "", err
	}
	if err = writeFail2banExistingCandidate(dir, c.afterSnapshot().Files); err != nil {
		return empty, "", err
	}
	if err = syncTree(dir); err != nil {
		return empty, "", err
	}
	if err = syncDir(root); err != nil {
		return empty, "", err
	}
	if err = syncDir(fail2banExistingDir(data)); err != nil {
		return empty, "", err
	}
	actual, err := readFail2banExistingConfigAt(dir)
	if err != nil || actual.hash() != c.afterSnapshot().hash() {
		return empty, "", errors.New("独立 reload 候选配置不匹配")
	}
	raw, err := fail2banManagedExec(ctx, python, fail2banExistingPolicyClientArgs(evidence.Program, c, dir, evidence.Capture.Binding.Socket, "-d"), 2*time.Second, 2<<20)
	if err != nil {
		return empty, "", errors.New("官方客户端无法编译受限单 jail 配置流")
	}
	commands, err := parseFail2banDump(raw, c.Plan.Name)
	if err != nil || fail2banDumpHash(commands) != c.After.DumpHash {
		return empty, "", errors.New("受限官方配置流与参数计划不一致")
	}
	return python, dir, nil
}
