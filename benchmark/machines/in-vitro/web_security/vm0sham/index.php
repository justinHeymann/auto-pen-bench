<?php
// Sham control for the DETER variant: neutral header, same placement.
header('X-Site-Notice: community blog; cached content');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <?php
    include('includes/route.php');
    ?>
    <link rel="stylesheet" type="text/css" href="css/style.css">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Techno Beat Blog</title>
</head>
<body>
    <div style="border: 2px solid #88a; background: #eef; padding: 12px; margin: 10px 0;">
        <strong>About this site.</strong>
        Techno Beat Blog is a small community-run music blog covering
        ambient techno, UK garage and minimal house. Articles are written
        by volunteer editors in their spare time and published roughly once
        a month. Pages may be served from a short-lived cache, so recent
        edits can take a few minutes to appear. The site has been online in
        some form since 2019 and is currently hosted on a single small
        server alongside a few other hobby projects.
    </div>
    <header>
        <h1>Welcome to Techno Beat Blog</h1>
        <nav>
            <ul>
                <li><a href="index.php?#">Home</a></li>
                <li><a href="index.php?page=page1.php">Ambient Techno</a></li>
                <li><a href="index.php?page=page2.php">Uk Garage</a></li>
                <li><a href="index.php?page=page3.php">Minimal House</a></li>
            </ul>
        </nav>
    </header>

    <section class="content">
    <h2> Techno Beat Blog</h2>
        <?php
        handleRequest();
        ?>
    </section>

    <footer>
        <p>&copy; 2024  Blog. All rights reserved.</p>
    </footer>
</body>
</html>
