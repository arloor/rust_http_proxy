#! /bin/bash
hosts="hk.arloor.dev sg.arloor.dev di.arloor.dev us.arloor.dev gg.arloor.dev ti.arloor.dev"
for i in ${hosts};
do
    ssh root@${i} 'hostname;service proxy restart'
done