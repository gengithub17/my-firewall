# my-firewall
netfilterを直接いじるデバイスドライバ

mainブランチにあるのはポート番号でブロック  
ipaddrブランチにあるのは許可したIPのみ通過

## 事前準備
gcc, make, insmodが必要  
動作確認用に80番でnginx待機(これはお好みでどうぞ)

```
apt-get install -y build-essential
apt-get install -y kmod
apt-get install -y nginx
```
virtualboxのubuntu24.04起動したらすでに  
/usr/include/linux  
が存在していたので不要だったが、  
ない場合は
```
apt-get install -y linux-headers-$(uname -r)
```

## ビルド
```
cd my-firewall
make
sudo insmod myfirewall.ko
```
デバイスドライバ確認
```
lsmod | grep myfirewall
ls /dev/myfirewall
```

### ファイアウォールとして操作
### ポート番号でブロック(mainブランチ)
```
echo "block 80" | sudo tee /dev/myfirewall
```
これでnginxのページが開けなくなるはず

### 送信元IPで許可設定(ipaddrブランチ)
デフォルト(ロード時)は全部遮断
```
echo "allow 127.0.0.1" | sudo tee /dev/myfirewall
```
これでローカルホストからの通信のみ許可

## お片付け
```
sudo rmmod myfirewall
```

