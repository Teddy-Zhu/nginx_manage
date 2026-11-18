#!/bin/bash
# Sourced by manage.sh after validating the local installation record.

lifecycle_dir=$data/.installation
lifecycle_marker=/etc/nginxpanel/install/lifecycle
lifecycle_state=
lifecycle_writer_held=no
lifecycle_intent_sha=$(sha256sum "$intent"); lifecycle_intent_sha=${lifecycle_intent_sha%% *}
if [[ -e $lifecycle_marker || -L $lifecycle_marker ]]; then
  trusted_file "$lifecycle_marker"
  [[ $(stat -c %s "$lifecycle_marker") -le 32 ]] || die '卸载状态记录无效'
  lifecycle_state=$(cat -- "$lifecycle_marker")
  case "$lifecycle_state" in uninstalling|purge-uninstalling|uninstalled|reinstalling|reinstalled|purging) ;; *) die '未知卸载状态，停止操作' ;; esac
fi

lifecycle_write_state() {
  local pending
  pending=$(mktemp /etc/nginxpanel/install/.lifecycle.XXXXXXXX)
  printf '%s\n' "$1" >"$pending"
  chmod 0600 "$pending"
  sync -f "$pending"
  mv -T -- "$pending" "$lifecycle_marker"
  sync -f /etc/nginxpanel/install
  lifecycle_state=$1
}
lifecycle_lock() {
  local tool current current_state=
  for tool in flock tar sha256sum find cp cmp install sync systemctl; do
    command -v "$tool" >/dev/null || die "卸载或重装缺少系统工具：$tool"
  done
  if [[ $lifecycle_state == purging && ! -e $data && ! -L $data ]]; then root_chain "${data%/*}"; else root_chain "$data"; fi
  root_chain /run
  if [[ ! -e /run/nginxpanel-install && ! -L /run/nginxpanel-install ]]; then install -d -m 0700 -o root -g root /run/nginxpanel-install; fi
  root_chain /run/nginxpanel-install
  if [[ -e /run/nginxpanel-install/lock || -L /run/nginxpanel-install/lock ]]; then trusted_file /run/nginxpanel-install/lock; fi
  exec 9>/run/nginxpanel-install/lock
  flock -n 9 || die '其他安装、卸载或端口修改操作正在执行'
  trusted_file "$intent"
  current=$(sha256sum "$intent"); current=${current%% *}
  [[ $current == "$lifecycle_intent_sha" ]] || die '安装记录已变化，请重新执行命令'
  if [[ -e $lifecycle_marker || -L $lifecycle_marker ]]; then
    trusted_file "$lifecycle_marker"
    current_state=$(cat -- "$lifecycle_marker")
  fi
  [[ $current_state == "$lifecycle_state" ]] || die '安装状态已变化，请重新执行命令'
  [[ ! -e $data/run/panel-service-hold.json && ! -L $data/run/panel-service-hold.json && ! -e $data/run/panel-writer-fence.json && ! -L $data/run/panel-writer-fence.json ]] || die '存在持久停机或恢复屏障，请沿原任务处理'
}
lifecycle_units() {
  local unit path
  lifecycle_unit_names=()
  for unit in nginxpanel.service nginxpanel-agent.service nginxpanel-nginx.service nginxpanel-fail2ban.service \
    nginxpanel-install@.service nginxpanel-switch@.service nginxpanel-core-update@.service nginxpanel-update@.service nginxpanel-agent-upgrade@.service \
    nginxpanel-image@.service nginxpanel-nginx-image@.service nginxpanel-fail2ban-python@.service; do
    path=/etc/systemd/system/$unit
    if [[ -e $path || -L $path ]]; then
      trusted_file "$path"
      lifecycle_unit_names+=("$unit")
    fi
  done
}
lifecycle_check_mounts() {
  local path=$1 mounted
  # rm --one-file-system does not protect nested bind mounts on the same FS.
  command -v findmnt >/dev/null || die '需要已有 findmnt 检查清理范围内的挂载点'
  mounted=$(findmnt --raw --noheadings --output TARGET) || die '无法读取挂载表'
  while IFS= read -r mounted; do
    [[ $mounted != "$path" && $mounted != "$path/"* ]] || die "清理范围中存在挂载点：$mounted；请先解除挂载"
  done <<<"$mounted"
}
lifecycle_check_workers() {
  local units unit load active sub rest
  units=$(systemctl list-units --all --plain --no-legend --no-pager 'nginxpanel-*@*.service') || die '无法核对独立维护进程'
  while read -r unit load active sub rest; do
    [[ -n $unit ]] || continue
    case "$active" in inactive|failed) ;; *) die "独立维护进程 $unit 尚未停止（$active），请先处理原任务" ;; esac
  done <<<"$units"
}
lifecycle_writer_lock() {
  local path=$data/run/panel-writer.lock
  root_chain "$data/run"
  [[ -f $path && ! -L $path && $(stat -c %u "$path") == 0 && $(stat -c %h "$path") == 1 && $(stat -c %a "$path") == 660 && $(stat -c %g "$path") == 0 ]] || die '面板写锁类型或归属不可信'
  exec 7<>"$path"
  flock -n 7 || die '仍有面板或恢复进程持有写锁，停止卸载'
  lifecycle_writer_held=yes
}
lifecycle_stop() {
  local unit state
  if [[ -f $compose ]]; then
    compose_command down --timeout 65 || die '无法停止并移除本应用容器，未清理安装文件'
  fi
  for unit in nginxpanel.service nginxpanel-fail2ban.service nginxpanel-nginx.service nginxpanel-agent.service; do
    if [[ -f /etc/systemd/system/$unit ]]; then
      systemctl stop "$unit" || die "无法停止 $unit，未清理安装文件"
      state=$(systemctl show --property=ActiveState --value "$unit") || die "无法核对 $unit 状态"
      case "$state" in inactive|failed) ;; *) die "$unit 未停止，停止卸载" ;; esac
    fi
  done
}
lifecycle_capture_running() {
  local unit state service running
  lifecycle_running_units=()
  lifecycle_running_containers=()
  for unit in nginxpanel-agent.service nginxpanel-nginx.service nginxpanel-fail2ban.service nginxpanel.service; do
    if [[ -f /etc/systemd/system/$unit ]]; then
      state=$(systemctl show --property=ActiveState --value "$unit") || die "无法核对 $unit 状态"
      case "$state" in active) lifecycle_running_units+=("$unit") ;; inactive|failed) ;; *) die "$unit 正在切换状态（$state），请稍后重试" ;; esac
    fi
  done
  if [[ -f $compose ]]; then
    for service in panel nginx; do
      if [[ $service == panel && $panel_mode != docker ]]; then continue; fi
      if [[ $service == nginx ]] && ! nginx_uses_compose; then continue; fi
      running=$(compose_command ps --status running -q "$service") || die '无法核对本应用容器状态'
      if [[ -n $running ]]; then lifecycle_running_containers+=("$service"); fi
    done
  fi
}
lifecycle_resume_running() {
  local unit
  # A rejected removal must leave the original installation usable.
  exec 7>&-
  lifecycle_writer_held=no
  for unit in "${lifecycle_running_units[@]}"; do
    systemctl start "$unit" || die "卸载检查未通过，恢复 $unit 失败；程序和数据未删除"
  done
  if ((${#lifecycle_running_containers[@]})); then
    compose_command up -d "${lifecycle_running_containers[@]}" || die '卸载检查未通过，恢复原容器失败；程序和数据未删除'
  fi
}
lifecycle_check_removal() {
  local checker=$1 output
  trusted_file "$checker"
  [[ -x $checker ]] || die '卸载检查程序不可执行'
  if output=$("$checker" installation-removal-prepare --data-dir "$data" 2>&1); then
    :
  elif [[ $output == *'unknown subcommand'* && $output == *'installation-removal-prepare'* ]]; then
    # Older checkers predate automatic empty registration. Keep their original
    # read-only checks, including refusal to remove manually managed rules.
    if ! output=$("$checker" installation-removal-check --data-dir "$data" 2>&1); then
      printf '%s\n' "$output" >&2
      if [[ $output == *'unknown subcommand'* && $output == *'installation-removal-check'* ]]; then
        printf '%s\n' '已安装程序缺少卸载检查命令。请从最新源码或完整安装包执行 sudo bash install.sh --uninstall（默认保留数据），完全卸载加 --purge；未使用环境全新安装加 --fresh。' >&2
      fi
      return 1
    fi
  else
    printf '%s\n' "$output" >&2
    return 1
  fi
  if [[ -n $output ]]; then printf '%s\n' "$output"; fi
}
lifecycle_validate_materials() {
  local digest expected name extra
  root_chain "$lifecycle_dir"
  for name in system.tar system.sha256 enabled running containers nginxpanel; do trusted_file "$lifecycle_dir/$name"; done
  read -r expected name extra <"$lifecycle_dir/system.sha256"
  [[ $expected =~ ^[0-9a-f]{64}$ && $name == "$lifecycle_dir/system.tar" && -z $extra ]] || die '重装材料校验记录无效'
  digest=$(sha256sum "$lifecycle_dir/system.tar"); digest=${digest%% *}
  [[ $digest == "$expected" ]] || die '重装材料散列不匹配，停止恢复'
}
lifecycle_snapshot() {
  local mode=$1 unit state snapshot
  root_chain /opt/nginxpanel
  root_chain /etc/nginxpanel
  if [[ -e $lifecycle_dir || -L $lifecycle_dir ]]; then
    if [[ -e $lifecycle_dir/purge-only || -L $lifecycle_dir/purge-only ]]; then
      trusted_file "$lifecycle_dir/purge-only"
      [[ $mode == purge ]] || die '完全卸载尚未完成，请续办 uninstall --purge'
      return
    fi
    # Recover a crash between publishing the completed materials and recording
    # the first removal phase. No installation files have been deleted yet.
    lifecycle_validate_materials
    tar --compare --file "$lifecycle_dir/system.tar" --acls --xattrs --selinux -C / || die '未完成卸载的重装材料与现有安装不同，请保留材料并处理差异'
    return
  fi
  snapshot=$(mktemp -d "$data/.installation.XXXXXXXX")
  chmod 0700 "$snapshot"
  if [[ $mode == purge ]]; then
    # Full removal needs no program archive or extra binary copy.
    : >"$snapshot/purge-only"
  else
    lifecycle_units
    : >"$snapshot/enabled"
    for unit in "${lifecycle_unit_names[@]}"; do
      if [[ $unit != *@.service ]]; then
        state=$(systemctl is-enabled "$unit" 2>/dev/null) || {
          case "$state" in disabled|static|indirect) ;; *) die "无法核对 $unit 开机设置：$state" ;; esac
        }
        case "$state" in enabled) printf '%s\n' "$unit" >>"$snapshot/enabled" ;; disabled|static|indirect) ;; *) die "不支持的服务启用状态：$unit / $state" ;; esac
      fi
    done
    local -a paths=(opt/nginxpanel etc/nginxpanel)
    for unit in "${lifecycle_unit_names[@]}"; do
      paths+=("etc/systemd/system/$unit")
      if [[ -e /etc/systemd/system/$unit.d || -L /etc/systemd/system/$unit.d ]]; then
        root_chain "/etc/systemd/system/$unit.d"
        lifecycle_check_mounts "/etc/systemd/system/$unit.d"
        paths+=("etc/systemd/system/$unit.d")
      fi
    done
    if [[ -e /etc/tmpfiles.d/nginxpanel.conf || -L /etc/tmpfiles.d/nginxpanel.conf ]]; then
      trusted_file /etc/tmpfiles.d/nginxpanel.conf
      paths+=(etc/tmpfiles.d/nginxpanel.conf)
    fi
    # Installation files only; the data tree stays in place with its identity,
    # ownership and encrypted materials intact.
    tar --create --file "$snapshot/system.tar" --one-file-system --acls --xattrs --selinux -C / -- "${paths[@]}" || die "重装材料保存失败；未删除安装文件，暂存目录：$snapshot"
    state=$(sha256sum "$snapshot/system.tar"); state=${state%% *}
    printf '%s  %s\n' "$state" "$lifecycle_dir/system.tar" >"$snapshot/system.sha256"
    : >"$snapshot/running"
    : >"$snapshot/containers"
    if ((${#lifecycle_running_units[@]})); then printf '%s\n' "${lifecycle_running_units[@]}" >"$snapshot/running"; fi
    if ((${#lifecycle_running_containers[@]})); then printf '%s\n' "${lifecycle_running_containers[@]}" >"$snapshot/containers"; fi
    install -m 0555 "$removal_checker" "$snapshot/nginxpanel"
    sync -f "$snapshot/system.tar"
  fi
  if [[ -e /etc/nginxpanel/selinux/nginxpanel_files.cil || -L /etc/nginxpanel/selinux/nginxpanel_files.cil ]]; then
    trusted_file /etc/nginxpanel/selinux/nginxpanel_files.cil
    cp -p -- /etc/nginxpanel/selinux/nginxpanel_files.cil "$snapshot/selinux.cil"
  fi
  sync -f "$snapshot"
  mv -T -- "$snapshot" "$lifecycle_dir"
  sync -f "$data"
  sync -f "$lifecycle_dir"
}
lifecycle_disable_units() {
  local unit
  lifecycle_units
  for unit in "${lifecycle_unit_names[@]}"; do
    if [[ $unit != *@.service ]]; then systemctl disable "$unit" || die "无法停用 $unit"; fi
  done
  for unit in "${lifecycle_unit_names[@]}"; do
    lifecycle_check_mounts "/etc/systemd/system/$unit.d"
    rm -f -- "/etc/systemd/system/$unit"
    rm -rf --one-file-system -- "/etc/systemd/system/$unit.d"
  done
  rm -f -- /etc/tmpfiles.d/nginxpanel.conf
  systemctl daemon-reload
}
lifecycle_remove_program() {
  local path
  # Keep the small local management entry and installation identity so the
  # user can restore or finish a previously interrupted removal.
  for path in /opt/nginxpanel/* /opt/nginxpanel/.[!.]* /opt/nginxpanel/..?*; do
    [[ -e $path || -L $path ]] || continue
    case "$path" in /opt/nginxpanel/manage.sh|/opt/nginxpanel/lifecycle.sh) continue ;; esac
    rm -rf --one-file-system -- "$path"
  done
  for path in /etc/nginxpanel/* /etc/nginxpanel/.[!.]* /etc/nginxpanel/..?*; do
    [[ -e $path || -L $path ]] || continue
    [[ $path != /etc/nginxpanel/install ]] || continue
    rm -rf --one-file-system -- "$path"
  done
  for path in /etc/nginxpanel/install/* /etc/nginxpanel/install/.[!.]* /etc/nginxpanel/install/..?*; do
    [[ -e $path || -L $path ]] || continue
    case "$path" in /etc/nginxpanel/install/intent|/etc/nginxpanel/install/lifecycle) continue ;; esac
    rm -rf --one-file-system -- "$path"
  done
}
lifecycle_uninstall() {
  local mode=$1 stopped=no removal_checker
  if [[ -z $lifecycle_state ]]; then
    if [[ -n $checker_binary ]]; then removal_checker=$checker_binary; else load_binary; removal_checker=$binary; fi
    lifecycle_check_workers
    lifecycle_check_mounts /opt/nginxpanel
    lifecycle_check_mounts /etc/nginxpanel
    if [[ $mode == purge ]]; then lifecycle_check_mounts "$data"; fi
    lifecycle_prepare_control
    lifecycle_capture_running
    lifecycle_stop
    lifecycle_writer_lock
    # The running Agent holds the host registration lock. Release its process
    # before preparing empty registrations, then recheck under the writer lock.
    if ! lifecycle_check_removal "$removal_checker"; then
      lifecycle_resume_running
      die '卸载检查未通过，已恢复原服务；程序和数据未删除，请先处理原任务'
    fi
    lifecycle_check_workers
    lifecycle_snapshot "$mode"
    if [[ -f $lifecycle_dir/purge-only ]]; then lifecycle_write_state purge-uninstalling; else lifecycle_write_state uninstalling; fi
    stopped=yes
  else
    [[ $lifecycle_state != reinstalling && $lifecycle_state != reinstalled ]] || die '重装尚未完成，请先续办 reinstall'
    [[ $lifecycle_state != purging || $mode == purge ]] || die '完全卸载尚未完成，请续办 uninstall --purge'
    [[ $lifecycle_state != purge-uninstalling || $mode == purge ]] || die '完全卸载尚未完成，请续办 uninstall --purge'
  fi
  if [[ $lifecycle_state != uninstalled && $lifecycle_state != purging ]]; then
    if [[ $stopped == no ]]; then
      lifecycle_stop
      lifecycle_writer_lock
      if [[ $lifecycle_state != purge-uninstalling ]]; then
        lifecycle_check_removal "${checker_binary:-$lifecycle_dir/nginxpanel}" || die '停机后卸载检查未通过；安装文件保留，请处理原任务后重试'
      fi
      lifecycle_check_workers
    fi
    lifecycle_disable_units
    lifecycle_remove_program
    if [[ $lifecycle_state == purge-uninstalling ]]; then lifecycle_write_state purging; else lifecycle_write_state uninstalled; fi
  fi
  if [[ $mode == purge ]]; then
    lifecycle_purge
  else
    printf '已卸载，数据与重装材料保留在：%s\n重新安装：sudo bash /opt/nginxpanel/manage.sh reinstall\n' "$data"
  fi
}
lifecycle_prepare_control() {
  local self target source pending
  self=$(readlink -e -- "$0") || die '无法读取管理脚本路径'
  trusted_file "$self"
  for target in /opt/nginxpanel/manage.sh /opt/nginxpanel/lifecycle.sh; do
    case "$target" in
      /opt/nginxpanel/manage.sh) source=$self ;;
      /opt/nginxpanel/lifecycle.sh) source=$lifecycle_helper ;;
    esac
    trusted_file "$source"
    if [[ -e $target || -L $target ]]; then
      trusted_file "$target"
      if cmp -s "$source" "$target"; then continue; fi
    fi
    pending=$(mktemp /opt/nginxpanel/.lifecycle-control.XXXXXXXX)
    install -m 0555 "$source" "$pending"
    sync -f "$pending"
    mv -T -- "$pending" "$target"
  done
  sync -f /opt/nginxpanel
}
lifecycle_purge() {
  local policy=$lifecycle_dir/selinux.cil modules priority name language extra current present=no
  local tool
  for tool in getent id cut userdel groupdel; do command -v "$tool" >/dev/null || die "完全卸载缺少系统工具：$tool"; done
  lifecycle_check_mounts "$data"
  lifecycle_check_mounts /opt/nginxpanel
  lifecycle_check_mounts /etc/nginxpanel
  lifecycle_check_mounts /run/nginxpanel-host
  lifecycle_check_mounts /run/nginxpanel-fail2ban
  if [[ $lifecycle_state != purging ]]; then
    if [[ $lifecycle_writer_held != yes ]]; then lifecycle_writer_lock; fi
    lifecycle_check_removal "${checker_binary:-$lifecycle_dir/nginxpanel}" || die '完全卸载前检查未通过，保留数据'
    lifecycle_check_workers
  fi
  lifecycle_write_state purging
  # Remove only the exact SELinux module installed by this application.
  if [[ -f $policy ]]; then
    trusted_file "$policy"
    command -v semodule >/dev/null || die '需要已有 semodule 移除本应用 SELinux 模块'
    modules=$(semodule -lfull 9>&- 7>&-) || die '无法读取 SELinux 模块登记'
    while read -r priority name language extra; do
      if [[ $name == nginxpanel_files ]]; then
        [[ $present == no && $priority == 400 && $language == cil && -z $extra ]] || die '本应用 SELinux 模块登记存在冲突'
        present=yes
      fi
    done <<<"$modules"
    if [[ $present == yes ]]; then
      current=$(mktemp -d "$lifecycle_dir/selinux-check.XXXXXXXX")
      (cd "$current" && semodule -X 400 --cil --extract=nginxpanel_files 9>&- 7>&-) || die '无法复核本应用 SELinux 模块'
      cmp -s "$policy" "$current/nginxpanel_files.cil" || die '本应用 SELinux 模块已被外部修改，停止移除'
      rm -rf -- "$current"
      semodule -X 400 --remove=nginxpanel_files 9>&- 7>&- || die 'SELinux 模块移除失败，保留清理记录，请重试完全卸载'
    fi
    rm -f -- "$policy"
  fi
  lifecycle_remove_accounts
  rm -rf --one-file-system -- "$data"
  rm -rf --one-file-system -- /run/nginxpanel-host /run/nginxpanel-fail2ban
  rm -rf --one-file-system -- /opt/nginxpanel
  rm -rf --one-file-system -- /etc/nginxpanel
  printf '%s\n' '完全卸载完成。重新安装请运行源码或 Release 安装入口。系统依赖、共享镜像和外部服务保留。'
}
lifecycle_remove_accounts() {
  local name entry account_name password uid gid comment account_home account_shell group_entry
  for name in nginxpanel nginxpanel-nginx; do
    if entry=$(getent passwd "$name"); then
      IFS=: read -r account_name password uid gid comment account_home account_shell <<<"$entry"
      [[ $account_name == "$name" && $uid =~ ^[1-9][0-9]*$ && $account_home == /nonexistent && $account_shell == /usr/sbin/nologin && $gid == "$(getent group "$name" | cut -d: -f3)" && $(id -G "$name") == "$gid" ]] || die "账户 $name 已被外部修改，停止删除"
      userdel "$name" || die "无法删除专用账户 $name"
    fi
  done
  for name in nginxpanel nginxpanel-nginx nginxpanel-ipc; do
    if group_entry=$(getent group "$name"); then
      [[ ${group_entry##*:} == '' ]] || die "专用组 $name 存在外部成员，停止删除"
      groupdel "$name" || die "无法删除专用组 $name"
    fi
  done
}
lifecycle_reinstall() {
  local unit service running restored_running=:
  if [[ -z $lifecycle_state ]]; then lifecycle_uninstall keep; fi
  if [[ $lifecycle_state == reinstalled ]]; then lifecycle_finish_reinstall; return; fi
  [[ $lifecycle_state == uninstalled || $lifecycle_state == reinstalling ]] || die '请先完成原卸载；完全卸载后须重新运行安装入口'
  lifecycle_validate_materials
  lifecycle_check_mounts /opt/nginxpanel
  lifecycle_check_mounts /etc/nginxpanel
  if [[ $lifecycle_state == reinstalling ]]; then lifecycle_stop; fi
  lifecycle_writer_lock
  lifecycle_write_state reinstalling
  tar --extract --file "$lifecycle_dir/system.tar" --same-owner --same-permissions --acls --xattrs --selinux -C / || die '安装文件恢复失败，请续办 reinstall'
  if [[ -f $lifecycle_dir/selinux.cil ]]; then
    trusted_file "$lifecycle_dir/selinux.cil"
    semodule -X 400 --install="$lifecycle_dir/selinux.cil" 9>&- 7>&- || die 'SELinux 模块恢复失败'
    restorecon -RFx /opt/nginxpanel /etc/nginxpanel "$data" 9>&- 7>&- || die 'SELinux 文件标签恢复失败'
  fi
  systemctl daemon-reload
  if [[ -f /etc/tmpfiles.d/nginxpanel.conf ]]; then systemd-tmpfiles --create /etc/tmpfiles.d/nginxpanel.conf; fi
  while IFS= read -r unit; do
    case "$unit" in nginxpanel.service|nginxpanel-agent.service|nginxpanel-nginx.service|nginxpanel-fail2ban.service) ;; *) die '重装材料包含未知服务' ;; esac
    trusted_file "/etc/systemd/system/$unit"
    systemctl enable "$unit" || die "无法恢复 $unit 开机设置"
  done <"$lifecycle_dir/enabled"
  exec 7>&-
  while IFS= read -r unit; do
    case "$unit" in nginxpanel.service|nginxpanel-agent.service|nginxpanel-nginx.service|nginxpanel-fail2ban.service) ;; *) die '重装材料包含未知运行服务' ;; esac
    systemctl start "$unit" || die "$unit 启动失败；原数据保留，请检查日志后续办 reinstall"
    systemctl is-active --quiet "$unit" || die "$unit 未进入运行状态，请检查后续办 reinstall"
    restored_running=$restored_running$unit:
  done <"$lifecycle_dir/running"
  while IFS= read -r service; do
    if [[ $service == nginx ]]; then
      nginx_uses_compose || die '重装材料缺少 Nginx 容器配置'
    else
      [[ $service == panel && $panel_mode == docker ]] || die '重装材料包含未知容器'
    fi
    compose_command up -d --no-deps --pull never "$service" || die '容器启动失败，请检查后续办 reinstall'
    running=$(compose_command ps --status running -q "$service") || die '无法核对恢复后的容器状态'
    [[ -n $running ]] || die '恢复后的容器未运行，请检查后续办 reinstall'
  done <"$lifecycle_dir/containers"
  # A unit's Wants may start a dependency that the administrator had stopped.
  for unit in nginxpanel.service nginxpanel-fail2ban.service nginxpanel-nginx.service nginxpanel-agent.service; do
    if [[ -f /etc/systemd/system/$unit && $restored_running != *":$unit:"* ]]; then
      systemctl stop "$unit" || die "无法恢复 $unit 的原停止状态"
    fi
  done
  lifecycle_write_state reinstalled
  lifecycle_finish_reinstall
}
lifecycle_finish_reinstall() {
  lifecycle_check_mounts "$lifecycle_dir"
  rm -rf --one-file-system -- "$lifecycle_dir"
  rm -f -- "$lifecycle_marker"
  sync -f /etc/nginxpanel/install
  printf '%s\n' '重新安装完成，原版本、节点身份、账号、配置、证书、监听端口及服务启停状态保持。'
  show_info
}
lifecycle_action() {
  case "$action" in
    uninstall)
      if [[ $purge == yes ]]; then
        confirm_change "完全卸载将永久删除本系统程序、配置、密钥、证书、备份及数据目录 $data，并停止代理服务。"
      else
        confirm_change "卸载将停止并移除本系统服务与运行程序，保留 $data 中的数据和重装材料。"
      fi
      lifecycle_lock
      local mode=keep
      if [[ $purge == yes ]]; then mode=purge; fi
      lifecycle_uninstall "$mode" ;;
    reinstall)
      confirm_change "重新安装将恢复卸载前的版本、配置及服务启停状态；运行中的代理会中断，数据目录为 $data。"
      lifecycle_lock
      lifecycle_reinstall ;;
  esac
}
