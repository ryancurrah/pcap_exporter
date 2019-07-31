#!/usr/bin/env bash
### BEGIN INIT INFO
# Provides: pcap_exporter
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start pcap_exporter at boot time
# Description:       Start pcap_exporter at boot time. pcap_exporter is a Prometheus metrics tool
### END INIT INFO

filter="dst net 10.0.0.0/8 and not src net 10.0.0.0/8 and not src net 172.16.0.0/12 and not src net 192.168.0.0/16 and not src net 224.0.0.0/22 and not src host 255.255.255.255"
listenAddress="10.0.7.1:9998"
dir="/root"
cmd="pcap_exporter -i eth1 -r -l-tp -f '${filter}' -listen-address '${listenAddress}'"
user=""

name="$(basename "${0}")"
pid_file="/var/run/$name.pid"
log="/var/log/$name.log"

get_pid() {
    cat "$pid_file"
}

is_running() {
    [ -f "$pid_file" ] && ps -p "$(get_pid)" > /dev/null 2>&1
}

case "$1" in
    start)
        if is_running; then
            echo "Already started"
        else
            echo "Starting $name"
            cd "${dir}" || exit
            if [ -z "$user" ]; then
                sudo "${cmd}" | sudo tee -a "$log" &
            else
                sudo -u "$user" "${cmd}" | sudo tee -a "$log" &
            fi
            echo $! > "$pid_file"
            if ! is_running; then
                echo "Unable to start, see $log"
                exit 1
            fi
        fi
    ;;
    stop)
        if is_running; then
            echo -n "Stopping $name.."
            kill "$(get_pid)"
            for i in {1..10}
            do
                if ! is_running; then
                    break
                fi

                echo -n "."
                sleep 1
            done
            echo

            if is_running; then
                echo "Not stopped; may still be shutting down or shutdown may have failed"
                exit 1
            else
                echo "Stopped"
                if [ -f "$pid_file" ]; then
                    rm "$pid_file"
                fi
            fi
        else
            echo "Not running"
        fi
    ;;
    restart)
        $0 stop
        if is_running; then
            echo "Unable to stop, will not attempt to start"
            exit 1
        fi
        $0 start
    ;;
    status)
        if is_running; then
            echo "Running"
        else
            echo "Stopped"
            exit 1
        fi
    ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
    ;;
esac

exit 0
