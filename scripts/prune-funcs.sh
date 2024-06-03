for tag in `cat func.list`
do
cnt=$(grep $tag */*.go | wc -l)
[ $cnt -eq  1 ] && echo $tag
done > unused.txt
