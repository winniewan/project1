function update_votes(){
    alert("Upvoted")
}


$(".up_arrow").each(function () {
        $(this).on('click', function () {
            update_votes();
        })
    }
);
