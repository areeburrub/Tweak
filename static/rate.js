ratebar = document.getElementById("rate-controller");
reaction = ratebar.getAttribute("reaction");
postId = document.getElementById("postid").getAttribute("postid");

seticon();

var dislike_btn = document.getElementById("dislike");
var like_btn = document.getElementById("like");
var smile_btn = document.getElementById("smile");

seticon();

dislike_btn.onclick = function Dislike() {
    if(reaction == "dislike"){
        reaction = "nothing"
        ratebar.setAttribute("reaction", "nothing");
        console.log(reaction)
        seticon();
        // var xhttp = new XMLHttpRequest();
        // xhttp.open("POST", "/rate", true);
        // xhttp.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
        // xhttp.send('Action=nothing&PostID=' + postId);
        $.ajax({
            type: "POST",
            url: "/rate",
            data: 'Action=nothing&PostID=' + postId,
            success: function () {}
        });
    }
    else if (reaction == "nothing"||"like"||"smile"){
        reaction = "dislike"
        ratebar.setAttribute("reaction", "dislike");
        console.log(reaction)
        seticon();
        $.ajax({
            type: "POST",
            url: "/rate",
            data: 'Action=dislike&PostID=' + postId,
            success: function () {}

        });
    } 
}

like_btn.onclick = function Like() {
    if(reaction == "like"){
        reaction = "nothing"
        ratebar.setAttribute("reaction", "nothing");
        console.log(reaction)
        seticon();
        $.ajax({
            type: "POST",
            url: "/rate",
            data: 'Action=nothing&PostID=' + postId,
            success: function () {}
        });
    }
    else if (reaction == "nothing"||"smile"||"dislike"){
        reaction = "like"
        ratebar.setAttribute("reaction", "like");
        console.log(reaction)
        seticon();
        $.ajax({
            type: "POST",
            url: "/rate",
            data: 'Action=like&PostID=' + postId,
            success: function () {}
        });
    } 
}

smile_btn.onclick = function Smile() {
    if(reaction == "smile"){
        reaction = "nothing"
        ratebar.setAttribute("reaction", "nothing");
        console.log(reaction)
        seticon();
        $.ajax({
            type: "POST",
            url: "/rate",
            data: 'Action=nothing&PostID=' + postId,
            success: function () {}
        });
    }
    else if (reaction == "dislike"||"nothing"||"like"){
        reaction = "smile"
        ratebar.setAttribute("reaction", "smile");
        console.log(reaction)
        seticon();
        $.ajax({
            type: "POST",
            url: "/rate",
            data: 'Action=dislike_smile&PostID=' + postId,
            success: function () {}
        });
    }  
}


function seticon(){
    dislike_element = document.getElementById("dislike-icon");
    like_element = document.getElementById("like-icon");
    smile_element = document.getElementById("smile-icon");

    if(reaction == "dislike"){

        dislike_element.classList.add("fa-thumbs-down-enlarge");
        like_element.classList.remove("fa-thumbs-up-enlarge");
        smile_element.classList.remove("fa-smile-enlarge");
    }

    if(reaction == "like"){

        dislike_element.classList.remove("fa-thumbs-down-enlarge");
        like_element.classList.add("fa-thumbs-up-enlarge");
        smile_element.classList.remove("fa-smile-enlarge");
    }

    if(reaction == "smile"){

        dislike_element.classList.remove("fa-thumbs-down-enlarge");
        like_element.classList.remove("fa-thumbs-up-enlarge");
        smile_element.classList.add("fa-smile-enlarge");
    }

    if(reaction == "nothing"){

        dislike_element.classList.remove("fa-thumbs-down-enlarge");
        like_element.classList.remove("fa-thumbs-up-enlarge");
        smile_element.classList.remove("fa-smile-enlarge");
    }
}