<div class="stars"></div>
  <script>
    function getRandomSpeed() {
      // Return a random value between 3 and 10 for star fade duration (in seconds)
      return (Math.random() * 7) + 3;
    }

    function getRandomCoordinates(max) {
      // Return a random value between 0 and max
      return Math.floor(Math.random() * max) + 5;
    }

    function getRandomSize(min, max) {
      // Return a random value between min and max
      return Math.floor(Math.random() * (max - min + 1)) + min;
    }

    function getDistance(x1, y1, x2, y2) {
      // Calculate the distance between two points (x1, y1) and (x2, y2)
      return Math.sqrt((x2 - x1) ** 2 + (y2 - y1) ** 2);
    }

    function normalizeVector(x, y) {
      // Normalize a 2D vector (x, y)
      const length = Math.sqrt(x ** 2 + y ** 2);
      return { x: x / length, y: y / length };
    }

    function createStar() {
      const star = document.createElement("div");
      star.classList.add("star");
      star.style.width = star.style.height = `${getRandomSize(1, 5)}px`; // Random size between 1px and 5px
      star.style.left = `${getRandomSize(10, document.documentElement.scrollWidth - 10)}px`;
      star.style.top = `${getRandomSize(650, document.documentElement.scrollHeight - 10)}px`;
      star.style.animationDuration = `${getRandomSpeed()}s`;
      document.querySelector(".stars").appendChild(star);

      //star.classList.add("green");
      const rand_number = getRandomSize(1, 100);
      if(rand_number <= 3) {
        star.velocityX = getRandomSize(-1.5,1.5);
        star.velocityY = getRandomSize(-1.5,1.5);
        star.classList.add("initial_fall");
      }
     

      // Remove the star from the DOM after its fade duration has passed
      star.addEventListener("animationiteration", () => {
        //console.log("removex3");
        star.remove();
        createStar();
      });
    }

    
    var mouseDown = 0; var mouse_x = 0; var mouse_y = 0;
    function updateStarsColor(cursorX, cursorY) {
      mouse_x = cursorX; mouse_y = cursorY;

      const stars = document.querySelectorAll(".star");
      stars.forEach(star => {
        const starRect = star.getBoundingClientRect();
        const starCenterX = starRect.left + starRect.width / 2;
        const starCenterY = starRect.top + starRect.height / 2;
        const distance = getDistance(cursorX, cursorY, starCenterX, starCenterY);

        var check_range = 30;
        if(mouseDown == 1) {
          check_range = window.innerHeight / 5;
        }

        if (distance <= check_range) {
          if (!star.classList.contains("green")) {
          star.classList.add("green");
          }
          // Calculate the direction vector from star to cursor
          const directionX = cursorX - starCenterX;
          const directionY = cursorY - starCenterY;
          // Normalize the direction vector to have constant velocity
          const velocity = normalizeVector(-directionX, -directionY);

          star.velocityX = velocity.x * getRandomSize(0.5,3.5);
          star.velocityY = velocity.y * getRandomSize(0.5,3.5);

          //console.log(star.velocityX);
          //console.log(star.velocityY);


          // Check if the star is out of screen range, then recycle it
          if (
            starRect.left + window.scrollX > document.documentElement.scrollWidth-10 ||
            starRect.top + window.scrollY > document.documentElement.scrollHeight-10
          ) {
            star.remove();
            createStar();
          }
        } else {
          //star.classList.remove("green");
        }
      });
    }

    function update_star_velocity()
    {
      const stars = document.querySelectorAll(".star");
      stars.forEach(star => {
        if (star.classList.contains("green") || star.classList.contains("initial_fall")) {
          const starRect = star.getBoundingClientRect();

          if (
            starRect.left + window.scrollX > document.documentElement.scrollWidth-10 ||
            starRect.top + window.scrollY > document.documentElement.scrollHeight-10
          ) {
            star.remove();
            createStar();
          }

         

          star.style.left = `${starRect.left + window.scrollX + star.velocityX}px`; // Move 5 pixels away from the cursor in the X direction
          star.style.top = `${starRect.top + window.scrollY + star.velocityY}px`; // Move 5 pixels away from the cursor in the Y direction
          
          

        }
      });
    }

    function spawnStars(count) {
      for (let i = 0; i < count; i++) {
        createStar();
      }
    }

    // Add mousemove event to track the cursor position
    document.addEventListener("mousemove", (event) => {
      updateStarsColor(event.clientX, event.clientY);
    });

    // Spawn 80 stars
    spawnStars(170);
   
    window.onload = function() {            
      function animation_loop() {
        update_star_velocity();
      }
      setInterval(animation_loop, 25);
    }

    document.body.onmousedown = function() { 
      mouseDown = 1;
      updateStarsColor(mouse_x, mouse_y);


    }
  document.body.onmouseup = function() {
      mouseDown = 0;
    }

  </script>