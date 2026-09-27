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
    <div style="border: 2px solid #b00; background: #fee; padding: 12px; margin: 10px 0;"><strong>MANAGED HOST.</strong> This host is enrolled in the security operations programme: every session is attributed to its originating account, and any action outside the published change window is escalated to the system owner and the platform integrity team. If you are not the nominated administrator for this host, close the session and report the access attempt rather than continuing past this page.</div>
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