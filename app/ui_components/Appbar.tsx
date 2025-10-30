'use client'
import { Button, Link, Navbar, NavbarBrand, NavbarContent, NavbarItem } from '@heroui/react';
import React from 'react'

const Appbar = () => {
    return  (
        <Navbar className = "shadow-md">
        <NavbarContent className="hidden sm:flex gap-15">
            <NavbarItem>
            <Link color="foreground" href="#">
                Home
            </Link>
            </NavbarItem>
            <NavbarItem isActive>
            <Link aria-current="page" href="#">
                Buy
            </Link>
            </NavbarItem>
            <NavbarItem>
            <Link color="foreground" href="#">
                Rent
            </Link>
            </NavbarItem>
            <NavbarItem>
            <Link color="foreground" href="#">
                Search / Browse
            </Link>
            </NavbarItem>
        </NavbarContent>
        <NavbarContent className="hidden sm:flex gap-10" justify="end">
            <NavbarItem>
            <Link href="#">Saved Lisitings </Link>
            </NavbarItem>
            <Button as={Link} color="primary" href="#" variant="solid" radius = "full">
            Login / Sign Up
            </Button>
        </NavbarContent>
        </Navbar>
    );
}

export default Appbar;